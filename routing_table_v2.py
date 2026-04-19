```python
"""
vrf_route_lookup.py - VRF-aware routing table query and prefix lookup tool

Purpose:
    Query routing tables on Cisco IOS/IOS-XE devices with support for VRF
    contexts, specific prefix lookups, and protocol filtering. Parses output
    into structured data for auditing next-hops, confirming route presence,
    and exporting per-VRF route summaries.

Usage:
    python vrf_route_lookup.py -d 192.168.1.1 -u admin -p secret
    python vrf_route_lookup.py -d 192.168.1.1 -u admin --vrf CUSTOMER-A
    python vrf_route_lookup.py -d 192.168.1.1 -u admin --prefix 10.0.0.0/8
    python vrf_route_lookup.py -d 192.168.1.1 -u admin --protocol bgp -o json

Prerequisites:
    pip install paramiko
    SSH enabled on target device with sufficient privilege to run 'show ip route'
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
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

PROTOCOL_CODES = {
    "C": "connected",
    "S": "static",
    "R": "rip",
    "M": "mobile",
    "B": "bgp",
    "D": "eigrp",
    "O": "ospf",
    "IA": "ospf-inter-area",
    "N1": "ospf-nssa-ext1",
    "N2": "ospf-nssa-ext2",
    "E1": "ospf-ext1",
    "E2": "ospf-ext2",
    "i": "isis",
    "L1": "isis-level-1",
    "L2": "isis-level-2",
    "ia": "isis-inter-area",
    "T": "traffic-engineered",
    "u": "per-user-static",
}

ROUTE_RE = re.compile(
    r"^([A-Za-z*]{1,2})\s{1,5}"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)"
    r"(?:\s+\[(\d+)/(\d+)\])?"
    r"(?:\s+via\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?"
    r"(?:,\s+(\S+))?"
)


def ssh_run(host, port, username, password, command, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, allow_agent=False, look_for_keys=False,
        )
        channel = client.invoke_shell()
        time.sleep(1)
        channel.recv(4096)
        channel.send("terminal length 0\n")
        time.sleep(0.5)
        channel.recv(4096)
        channel.send(command + "\n")
        time.sleep(2)
        output = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(8192)
                output += chunk
                if output.rstrip().endswith(b"#") or output.rstrip().endswith(b">"):
                    break
            else:
                time.sleep(0.3)
        return output.decode("utf-8", errors="replace")
    finally:
        client.close()


def build_command(vrf, prefix):
    if prefix:
        base = f"show ip route {prefix}"
    else:
        base = "show ip route"
    if vrf:
        base = f"show ip route vrf {vrf}" + (f" {prefix}" if prefix else "")
    return base


def parse_routes(raw, protocol_filter=None):
    routes = []
    for line in raw.splitlines():
        line = line.strip()
        m = ROUTE_RE.match(line)
        if not m:
            continue
        code = m.group(1).lstrip("*").strip()
        proto = PROTOCOL_CODES.get(code, code.lower())
        if protocol_filter and proto != protocol_filter:
            continue
        routes.append({
            "protocol": proto,
            "code": code,
            "network": m.group(2),
            "admin_distance": m.group(3),
            "metric": m.group(4),
            "next_hop": m.group(5),
            "interface": m.group(6),
        })
    return routes


def print_table(routes):
    if not routes:
        print("No matching routes found.")
        return
    header = f"{'Protocol':<12} {'Network':<20} {'Next-Hop':<18} {'AD/Metric':<12} {'Interface'}"
    print(header)
    print("-" * len(header))
    for r in routes:
        ad_metric = (
            f"{r['admin_distance']}/{r['metric']}"
            if r["admin_distance"] else ""
        )
        print(
            f"{r['protocol']:<12} {r['network']:<20} "
            f"{r['next_hop'] or '':<18} {ad_metric:<12} {r['interface'] or ''}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="VRF-aware routing table query for Cisco IOS/IOS-XE"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", help="VRF name to query")
    parser.add_argument("--prefix", help="Specific destination prefix to look up")
    parser.add_argument(
        "--protocol",
        choices=list(set(PROTOCOL_CODES.values())),
        help="Filter results by routing protocol",
    )
    parser.add_argument(
        "-o", "--output", choices=["table", "json"], default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    command = build_command(args.vrf, args.prefix)
    log.info("Connecting to %s:%d", args.device, args.port)
    log.info("Running: %s", command)

    try:
        raw = ssh_run(args.device, args.port, args.username, password, command, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    routes = parse_routes(raw, protocol_filter=args.protocol)
    log.info("Parsed %d route(s)", len(routes))

    if args.output == "json":
        print(json.dumps(routes, indent=2))
    else:
        print_table(routes)


if __name__ == "__main__":
    main()
```