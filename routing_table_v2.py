```python
"""
BGP Neighbor Status - paramiko-network-scripts

Connects to a Cisco IOS/IOS-XE device via SSH, retrieves the BGP neighbor
summary, and displays peer states, AS numbers, prefix counts, and session uptime.

Usage:
    python bgp_neighbor_status.py -d 192.168.1.1 -u admin -p secret
    python bgp_neighbor_status.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python bgp_neighbor_status.py -d 192.168.1.1 -u admin -p secret --vrf CORP
    python bgp_neighbor_status.py -d 192.168.1.1 -u admin -p secret --filter-state Active --json

Prerequisites:
    pip install paramiko
    Device must have BGP configured and SSH enabled (ip ssh version 2).
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

BGP_NEIGHBOR_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"\d+\s+"
    r"(\d+)\s+"
    r"(\d+)\s+"
    r"(\d+)\s+"
    r"\S+\s+"
    r"\d+\s+"
    r"\d+\s+"
    r"(\S+)\s+"
    r"(\S+)$",
    re.MULTILINE,
)


def connect(host, username, password=None, key_file=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username, timeout=timeout)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, recv_wait=2.5):
    shell = client.invoke_shell(width=220, height=50)
    shell.settimeout(recv_wait + 5)
    time.sleep(0.6)
    shell.recv(8192)  # discard login banner
    shell.sendall("terminal length 0\n")
    time.sleep(0.4)
    shell.recv(8192)
    shell.sendall(command + "\n")
    time.sleep(recv_wait)
    buf = b""
    while shell.recv_ready():
        buf += shell.recv(16384)
    shell.close()
    return buf.decode("utf-8", errors="replace")


def parse_bgp_summary(output):
    local_as = None
    router_id = None

    m = re.search(r"local AS number (\d+)", output, re.IGNORECASE)
    if m:
        local_as = m.group(1)

    m = re.search(r"BGP router identifier (\d+\.\d+\.\d+\.\d+)", output, re.IGNORECASE)
    if m:
        router_id = m.group(1)

    neighbors = []
    for match in BGP_NEIGHBOR_RE.finditer(output):
        peer_ip, remote_as, msg_rcvd, msg_sent, updown, state_pfx = match.groups()
        try:
            prefixes = int(state_pfx)
            state = "Established"
        except ValueError:
            prefixes = None
            state = state_pfx

        neighbors.append({
            "neighbor": peer_ip,
            "remote_as": remote_as,
            "state": state,
            "prefixes_received": prefixes,
            "updown": updown,
            "msg_rcvd": int(msg_rcvd),
            "msg_sent": int(msg_sent),
        })

    return {"router_id": router_id, "local_as": local_as, "neighbors": neighbors}


def print_table(data, filter_state=None):
    neighbors = data["neighbors"]
    if filter_state:
        neighbors = [n for n in neighbors if n["state"].lower() == filter_state.lower()]

    if not neighbors:
        print("No BGP neighbors matched.")
        return

    rid = data["router_id"] or "unknown"
    las = data["local_as"] or "unknown"
    print(f"\nBGP Router ID: {rid}   Local AS: {las}\n")

    header = f"{'Neighbor':<18} {'Remote AS':<12} {'State':<14} {'Prefixes':>8}  {'Up/Down':<14} {'MsgRcvd':>8} {'MsgSent':>8}"
    print(header)
    print("-" * len(header))

    for n in neighbors:
        pfx = str(n["prefixes_received"]) if n["prefixes_received"] is not None else "-"
        print(
            f"{n['neighbor']:<18} {n['remote_as']:<12} {n['state']:<14} {pfx:>8}  "
            f"{n['updown']:<14} {n['msg_rcvd']:>8} {n['msg_sent']:>8}"
        )

    total = len(neighbors)
    up = sum(1 for n in neighbors if n["state"] == "Established")
    print(f"\nTotal: {total}   Established: {up}   Not established: {total - up}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Retrieve BGP neighbor summary from a network device via SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_file", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", default=None, help="VRF name for VPN BGP summary")
    parser.add_argument(
        "--filter-state",
        dest="filter_state",
        metavar="STATE",
        default=None,
        help="Show only neighbors matching this state (e.g. Established, Active, Idle)",
    )
    parser.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    command = (
        f"show ip bgp vpnv4 vrf {args.vrf} summary" if args.vrf else "show ip bgp summary"
    )

    try:
        logger.debug("Connecting to %s:%d as %s", args.device, args.port, args.username)
        client = connect(
            args.device, args.username,
            password=args.password, key_file=args.key_file, port=args.port,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        raw = run_command(client, command)
        logger.debug("Raw output:\n%s", raw)
    except Exception as exc:
        logger.error("Command execution failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    if "Invalid input" in raw or "% BGP" in raw:
        print(f"Device error:\n{raw}", file=sys.stderr)
        sys.exit(1)

    data = parse_bgp_summary(raw)

    if args.as_json:
        print(json.dumps(data, indent=2))
    else:
        print_table(data, filter_state=args.filter_state)


if __name__ == "__main__":
    main()
```