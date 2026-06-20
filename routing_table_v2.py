Here's the script — `bgp_neighbor_monitor.py`. It's distinct from `routing_table.py`/`routing_table_v2.py` (which dump the FIB) by focusing on BGP control-plane peer state: neighbor IP, remote AS, session state (Established/Idle/Active/etc.), uptime, and received prefix count.

```python
"""
BGP Neighbor State Monitor

Purpose:
    Connect to a Cisco IOS/IOS-XE router via SSH and retrieve BGP neighbor
    summary data. Parses peer state, uptime, and received prefix counts.
    Useful for health checks, alerting on non-Established peers, and
    exporting peer state snapshots to JSON for comparison over time.

Usage:
    python bgp_neighbor_monitor.py -d 192.168.1.1 -u admin -p secret
    python bgp_neighbor_monitor.py -d 10.0.0.1 -u admin --key ~/.ssh/id_rsa
    python bgp_neighbor_monitor.py -d 10.0.0.1 -u admin -p secret --vrf MGMT --filter-state
    python bgp_neighbor_monitor.py -d 10.0.0.1 -u admin -p secret --json peers.json

Prerequisites:
    pip install paramiko
    SSH enabled on target device; BGP configured.
"""

import argparse
import json
import logging
import re
import sys
import time
from getpass import getpass

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

COMMAND_DELAY = 1.5
RECV_TIMEOUT = 15


def ssh_connect(host, port, username, password=None, key_path=None, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_path),
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
    elif password:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(shell, command, timeout=RECV_TIMEOUT):
    shell.send(command + "\n")
    time.sleep(COMMAND_DELAY)
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            output += shell.recv(65535).decode("utf-8", errors="replace")
            if re.search(r"[#>]\s*$", output.rstrip()):
                break
        time.sleep(0.1)
    return output


def parse_bgp_summary(output):
    """
    Parse IOS/IOS-XE 'show ip bgp summary' output.
    Returns list of peer dicts. Last column is either a prefix count
    (Established) or a state string (Idle, Active, Connect, etc.).
    """
    peers = []
    peer_re = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+"
        r"\d+\s+"          # BGP version
        r"(\d+)\s+"        # remote AS
        r"\d+\s+"          # MsgRcvd
        r"\d+\s+"          # MsgSent
        r"\d+\s+"          # TblVer
        r"\d+\s+"          # InQ
        r"(\S+)\s+"        # uptime
        r"(\S+)"           # prefix count or state word
    )
    for line in output.splitlines():
        m = peer_re.match(line.strip())
        if not m:
            continue
        neighbor, remote_as, uptime, pfx_or_state = m.groups()
        if pfx_or_state.isdigit():
            state = "Established"
            pfx_received = int(pfx_or_state)
        else:
            state = pfx_or_state
            pfx_received = 0
        peers.append({
            "neighbor": neighbor,
            "remote_as": int(remote_as),
            "uptime": uptime,
            "state": state,
            "prefixes_received": pfx_received,
        })
    return peers


def extract_local_as(output):
    m = re.search(r"local AS number (\d+)", output, re.IGNORECASE)
    return int(m.group(1)) if m else None


def print_peers(peers, local_as, filter_state):
    col = "{:<18} {:<12} {:<14} {:<12} {:>10}"
    header = col.format("Neighbor", "Remote AS", "State", "Uptime", "Pfx Rcvd")
    sep = "-" * len(header)
    print(f"\nLocal AS: {local_as or 'unknown'}")
    print(sep)
    print(header)
    print(sep)
    shown = 0
    for p in peers:
        if filter_state and p["state"] == "Established":
            continue
        pfx = str(p["prefixes_received"]) if p["state"] == "Established" else "-"
        print(col.format(p["neighbor"], p["remote_as"], p["state"], p["uptime"], pfx))
        shown += 1
    print(sep)
    total = len(peers)
    established = sum(1 for p in peers if p["state"] == "Established")
    print(
        f"Total: {total}  Established: {established}"
        f"  Non-established: {total - established}"
    )
    if filter_state and shown == 0:
        print("(all peers are Established)")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor BGP neighbor states on a Cisco IOS/IOS-XE device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_path", metavar="FILE", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", default=None, help="VRF name for VPNv4 summary")
    parser.add_argument(
        "--filter-state", action="store_true",
        help="Display only non-Established peers"
    )
    parser.add_argument(
        "--json", dest="json_output", metavar="FILE",
        help="Write peer data to JSON file"
    )
    parser.add_argument("--timeout", type=int, default=10, help="SSH connect timeout (seconds)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_path:
        password = getpass(f"Password for {args.username}@{args.device}: ")

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(
            args.device, args.port, args.username,
            password=password, key_path=args.key_path, timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell(width=200, height=200)
        time.sleep(1)
        shell.recv(65535)  # flush login banner

        run_command(shell, "terminal length 0")

        cmd = "show ip bgp summary"
        if args.vrf:
            cmd = f"show ip bgp vpnv4 vrf {args.vrf} summary"

        log.debug("Running: %s", cmd)
        output = run_command(shell, cmd)

        peers = parse_bgp_summary(output)
        local_as = extract_local_as(output)

        if not peers:
            log.warning("No BGP peers parsed — BGP may not be configured, or try --vrf")
            sys.exit(0)

        print_peers(peers, local_as, args.filter_state)

        if args.json_output:
            payload = {
                "device": args.device,
                "local_as": local_as,
                "vrf": args.vrf or "default",
                "peers": peers,
            }
            with open(args.json_output, "w") as fh:
                json.dump(payload, fh, indent=2)
            log.info("Peer data written to %s", args.json_output)

    finally:
        client.close()


if __name__ == "__main__":
    main()
```

**Key design choices:**
- Targets `show ip bgp summary` (IOS/IOS-XE) — distinct from the routing table scripts which read the FIB
- `--filter-state` flag is useful in monitoring pipelines: pipe output through alerting when any peer is non-Established
- `--vrf` switches to `show ip bgp vpnv4 vrf <name> summary` for MPLS VPN environments
- `--json` enables snapshot exports for before/after change comparisons
- Regex handles both Established (numeric prefix count) and non-Established (state word) in the last column, which is the standard IOS output format