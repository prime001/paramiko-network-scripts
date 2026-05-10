bgp_summary.py - BGP Neighbor State Parser

Connect to a Cisco IOS/IOS-XE router via SSH, collect 'show ip bgp summary'
output, and produce structured JSON or a tabular report showing neighbor state,
uptime, and prefix counts.

Practical uses:
  - NOC dashboards and automated health checks
  - Pre/post change-window verification
  - Alerting scripts that need a fast established/down tally

Usage:
    python bgp_summary.py -H 192.168.1.1 -u admin -p secret
    python bgp_summary.py -H 10.0.0.1 -u admin -k ~/.ssh/id_rsa --json
    python bgp_summary.py -H 10.0.0.1 -u admin -p secret --filter down

Prerequisites:
    pip install paramiko
    SSH must be enabled on the device; user needs at least privilege 1.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
log = logging.getLogger(__name__)

# Matches a BGP neighbor line from IOS 'show ip bgp summary':
# 10.0.0.1  4  65001  1234  5678  100  0  0  00:10:11  50
_NEIGHBOR_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<version>\d)\s+"
    r"(?P<asn>\d+)\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<tbl_ver>\d+)\s+"
    r"(?P<in_q>\d+)\s+"
    r"(?P<out_q>\d+)\s+"
    r"(?P<updown>\S+)\s+"
    r"(?P<state_pfx>\S+)$"
)


def connect(host, username, password=None, key_file=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=bool(key_file),
        allow_agent=False,
    )
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.warning("stderr from device: %s", err)
    return output


def parse_bgp_summary(raw):
    router_id = None
    local_as = None
    neighbors = []

    for line in raw.splitlines():
        m = re.search(r"BGP router identifier (\S+), local AS number (\d+)", line)
        if m:
            router_id = m.group(1)
            local_as = m.group(2)
            continue

        m = _NEIGHBOR_RE.match(line.strip())
        if not m:
            continue

        state_pfx = m.group("state_pfx")
        try:
            prefix_count = int(state_pfx)
            state = "Established"
        except ValueError:
            prefix_count = None
            state = state_pfx  # Idle, Active, Connect, OpenSent, OpenConfirm

        neighbors.append({
            "neighbor": m.group("neighbor"),
            "asn": int(m.group("asn")),
            "updown": m.group("updown"),
            "state": state,
            "prefixes_received": prefix_count,
            "msg_rcvd": int(m.group("msg_rcvd")),
            "msg_sent": int(m.group("msg_sent")),
        })

    return {"router_id": router_id, "local_as": local_as, "neighbors": neighbors}


def print_table(data):
    neighbors = data["neighbors"]
    router_id = data.get("router_id", "unknown")
    local_as = data.get("local_as", "unknown")

    print(f"Router ID : {router_id}   Local AS : {local_as}")

    if not neighbors:
        print("No BGP neighbors found in output.")
        return

    hdr = f"{'Neighbor':<16} {'Peer AS':<10} {'State':<14} {'Up/Down':<12} {'Pfx Rcvd':>8}"
    bar = "-" * len(hdr)
    print(bar)
    print(hdr)
    print(bar)
    for n in neighbors:
        pfx = str(n["prefixes_received"]) if n["prefixes_received"] is not None else "-"
        print(f"{n['neighbor']:<16} {n['asn']:<10} {n['state']:<14} {n['updown']:<12} {pfx:>8}")
    print(bar)

    total = len(neighbors)
    up = sum(1 for n in neighbors if n["state"] == "Established")
    print(f"Summary : {total} neighbors   {up} Established   {total - up} not Established")


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Parse BGP neighbor state from a Cisco IOS/IOS-XE router."
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("-k", "--key-file", default=None, dest="key_file",
                   help="Path to SSH private key")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--json", action="store_true", dest="json_out",
                   help="Emit JSON instead of a table")
    p.add_argument(
        "--filter",
        choices=["established", "down", "all"],
        default="all",
        help="Limit output to a neighbor subset (default: all)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        log.debug("Connecting to %s:%d as %s", args.host, args.port, args.username)
        client = connect(
            args.host,
            args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.host}", file=sys.stderr)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        print(f"ERROR: Cannot connect to {args.host}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = run_command(client, "show ip bgp summary")
    except paramiko.SSHException as exc:
        print(f"ERROR: Command execution failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

    data = parse_bgp_summary(raw)

    if args.filter == "established":
        data["neighbors"] = [n for n in data["neighbors"] if n["state"] == "Established"]
    elif args.filter == "down":
        data["neighbors"] = [n for n in data["neighbors"] if n["state"] != "Established"]

    if args.json_out:
        print(json.dumps(data, indent=2))
    else:
        print_table(data)