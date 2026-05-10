```python
"""
bgp_session_monitor.py - BGP Neighbor Session Monitor

Purpose:
    Connects to a Cisco IOS/IOS-XE device via SSH and reports BGP neighbor
    state, remote AS number, received prefix count, and session uptime.
    Supports per-VRF queries, single-neighbor filtering, JSON output, and
    an alerting exit code for use in monitoring pipelines.

Usage:
    python bgp_session_monitor.py -d 192.168.1.1 -u admin -p secret
    python bgp_session_monitor.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python bgp_session_monitor.py -d 192.168.1.1 -u admin -p secret --vrf MGMT
    python bgp_session_monitor.py -d 192.168.1.1 -u admin -p secret --json
    python bgp_session_monitor.py -d 192.168.1.1 -u admin -p secret --alert-on-down

Prerequisites:
    pip install paramiko
    SSH must be enabled on the device. User requires privilege level 1 or above.
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


def ssh_connect(host, port, username, password=None, key_file=None, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_file),
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key")
    try:
        client.connect(**kwargs)
        logger.info("Connected to %s:%d", host, port)
        return client
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as exc:
        logger.error("SSH negotiation failed for %s: %s", host, exc)
        raise


def run_command(client, command, timeout=30):
    channel = client.get_transport().open_session()
    channel.settimeout(timeout)
    channel.exec_command(command)
    output = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            output += channel.recv(65535)
        if channel.exit_status_ready():
            while channel.recv_ready():
                output += channel.recv(65535)
            break
        time.sleep(0.1)
    channel.close()
    return output.decode("utf-8", errors="replace")


def parse_bgp_summary(raw):
    router_id, local_as = None, None
    header_match = re.search(
        r"BGP router identifier (\d+\.\d+\.\d+\.\d+), local AS number (\d+)", raw
    )
    if header_match:
        router_id = header_match.group(1)
        local_as = int(header_match.group(2))

    # Cisco IOS BGP summary neighbor line:
    # Neighbor  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
    pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\S+\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
        re.MULTILINE,
    )
    neighbors = []
    for m in pattern.finditer(raw):
        neighbor, remote_as, uptime, state_or_pfx = m.groups()
        try:
            prefix_count = int(state_or_pfx)
            state = "Established"
        except ValueError:
            prefix_count = 0
            state = state_or_pfx  # Idle, Active, Connect, OpenSent, etc.
        neighbors.append({
            "neighbor": neighbor,
            "remote_as": int(remote_as),
            "uptime": uptime,
            "state": state,
            "prefixes_received": prefix_count,
        })
    return {"router_id": router_id, "local_as": local_as, "neighbors": neighbors}


def display_results(data, host):
    print(f"\nBGP Summary — {host}")
    print(f"  Router-ID : {data['router_id'] or 'unknown'}")
    print(f"  Local AS  : {data['local_as'] or 'unknown'}")
    neighbors = data["neighbors"]
    if not neighbors:
        print("  No BGP neighbors found or BGP not configured.")
        return
    print()
    print(f"  {'Neighbor':<18}{'Remote-AS':<12}{'State':<16}{'Pfx-Rcvd':<10}{'Uptime'}")
    print("  " + "-" * 68)
    down = 0
    for n in neighbors:
        flag = " *" if n["state"] != "Established" else ""
        print(
            f"  {n['neighbor']:<18}{n['remote_as']:<12}{n['state']:<16}"
            f"{n['prefixes_received']:<10}{n['uptime']}{flag}"
        )
        if n["state"] != "Established":
            down += 1
    print(f"\n  Total: {len(neighbors)} neighbor(s), {down} not established")
    if down:
        print("  (* = session not established)")


def build_args():
    p = argparse.ArgumentParser(
        description="BGP neighbor session monitor via SSH (Cisco IOS/IOS-XE)"
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--key", dest="key_file", help="Path to SSH private key")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--vrf", help="VRF name to query BGP summary within")
    p.add_argument("--neighbor", help="Filter output to a specific neighbor IP")
    p.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")
    p.add_argument(
        "--alert-on-down",
        action="store_true",
        help="Exit with code 1 if any BGP session is not Established",
    )
    p.add_argument("--timeout", type=int, default=10, help="SSH connect timeout in seconds")
    return p.parse_args()


if __name__ == "__main__":
    args = build_args()

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = ssh_connect(
            args.device, args.port, args.username, args.password, args.key_file, args.timeout
        )
    except Exception as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        vrf_clause = f"vrf {args.vrf} " if args.vrf else ""
        command = f"show ip bgp {vrf_clause}summary"
        logger.debug("Executing: %s", command)
        raw = run_command(client, command)

        if not raw.strip() or "% Invalid" in raw or "% BGP not active" in raw:
            logger.error("Command returned an error or BGP is not configured:\n%s", raw[:300])
            sys.exit(1)

        data = parse_bgp_summary(raw)

        if args.neighbor:
            data["neighbors"] = [n for n in data["neighbors"] if n["neighbor"] == args.neighbor]
            if not data["neighbors"]:
                logger.warning("Neighbor %s not found in BGP summary", args.neighbor)

        if args.as_json:
            print(json.dumps(data, indent=2))
        else:
            display_results(data, args.device)

        if args.alert_on_down:
            down = [n for n in data["neighbors"] if n["state"] != "Established"]
            if down:
                logger.warning(
                    "%d session(s) not established: %s",
                    len(down),
                    ", ".join(n["neighbor"] for n in down),
                )
                sys.exit(1)
    finally:
        client.close()
        logger.debug("SSH connection closed")
```