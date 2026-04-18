```python
#!/usr/bin/env python3
"""
routing_table_filter.py - Routing Table Filter and Prefix Lookup Tool

Purpose:
    Connects to a network device via SSH and retrieves the routing table,
    then filters results by protocol, next-hop, or performs a longest-prefix
    match lookup for a specific destination. Useful for troubleshooting
    reachability issues and auditing routing policy.

Usage:
    python routing_table_filter.py -d 192.168.1.1 -u admin -p secret
    python routing_table_filter.py -d 192.168.1.1 -u admin --protocol ospf
    python routing_table_filter.py -d 192.168.1.1 -u admin --lookup 10.0.0.1
    python routing_table_filter.py -d 192.168.1.1 -u admin --next-hop 10.255.0.1
    python routing_table_filter.py -d 192.168.1.1 -u admin --protocol bgp --output routes.json

Prerequisites:
    pip install paramiko
    SSH access to target device (Cisco IOS/IOS-XE/NX-OS)
"""

import argparse
import getpass
import ipaddress
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
logger = logging.getLogger(__name__)

PROTOCOL_MAP = {
    "C": "connected", "S": "static", "R": "rip",
    "O": "ospf", "B": "bgp", "D": "eigrp",
    "i": "isis", "E": "eigrp-ext", "EX": "eigrp-ext",
    "IA": "ospf-inter", "N1": "ospf-nssa", "N2": "ospf-nssa",
    "E1": "ospf-ext1", "E2": "ospf-ext2",
}

ROUTE_RE = re.compile(
    r"^([A-Z*]{1,3}(?:\s[A-Z]{1,2})?)\s+"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)"
    r"(?:\s+\[(\d+)/(\d+)\])?"
    r"(?:\s+via\s+([\d.]+))?"
    r"(?:,\s+(\S+))?"
)


def ssh_connect(host, username, password, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
        )
        logger.info("Connected to %s:%d", host, port)
        return client
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        logger.error("SSH error connecting to %s: %s", host, exc)
        sys.exit(1)


def run_command(client, command, wait=2.0):
    channel = client.invoke_shell()
    channel.settimeout(10)
    time.sleep(0.5)
    channel.recv(4096)  # flush banner

    channel.send("terminal length 0\n")
    time.sleep(0.3)
    channel.recv(4096)

    channel.send(command + "\n")
    time.sleep(wait)

    output = ""
    while channel.recv_ready():
        output += channel.recv(8192).decode("utf-8", errors="replace")
        time.sleep(0.2)

    channel.close()
    return output


def parse_routes(raw_output):
    routes = []
    for line in raw_output.splitlines():
        line = line.rstrip()
        match = ROUTE_RE.match(line.lstrip())
        if not match:
            continue
        proto_code = match.group(1).strip().replace(" ", "")
        prefix_str = match.group(2)
        admin_dist = match.group(3)
        metric = match.group(4)
        next_hop = match.group(5)
        interface = match.group(6)

        if "/" not in prefix_str:
            prefix_str += "/32"

        try:
            network = ipaddress.ip_network(prefix_str, strict=False)
        except ValueError:
            continue

        protocol_name = PROTOCOL_MAP.get(proto_code, proto_code.lower())

        routes.append({
            "prefix": str(network),
            "protocol": protocol_name,
            "protocol_code": proto_code,
            "admin_distance": int(admin_dist) if admin_dist else None,
            "metric": int(metric) if metric else None,
            "next_hop": next_hop,
            "interface": interface,
        })

    return routes


def filter_by_protocol(routes, protocol):
    proto_lower = protocol.lower()
    return [
        r for r in routes
        if proto_lower in r["protocol"] or proto_lower == r["protocol_code"].lower()
    ]


def filter_by_next_hop(routes, next_hop):
    return [r for r in routes if r.get("next_hop") == next_hop]


def lookup_prefix(routes, destination):
    try:
        dest_ip = ipaddress.ip_address(destination)
    except ValueError:
        logger.error("Invalid IP address: %s", destination)
        return []

    matches = []
    for route in routes:
        try:
            network = ipaddress.ip_network(route["prefix"], strict=False)
            if dest_ip in network:
                matches.append(route)
        except ValueError:
            continue

    matches.sort(
        key=lambda r: ipaddress.ip_network(r["prefix"], strict=False).prefixlen,
        reverse=True,
    )
    return matches


def display_routes(routes, title="Routing Table"):
    print(f"\n{'='*60}")
    print(f"  {title}  ({len(routes)} entries)")
    print(f"{'='*60}")
    print(f"{'PREFIX':<22} {'PROTO':<12} {'AD/MET':<10} {'NEXT-HOP':<18} {'IFACE'}")
    print("-" * 80)
    for r in routes:
        ad_met = (
            f"{r['admin_distance']}/{r['metric']}"
            if r["admin_distance"] is not None else "-"
        )
        print(
            f"{r['prefix']:<22} {r['protocol']:<12} {ad_met:<10} "
            f"{r['next_hop'] or '-':<18} {r['interface'] or '-'}"
        )
    print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Retrieve and filter routing table entries from a network device",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--protocol", help="Filter by routing protocol (ospf, bgp, static, etc.)")
    parser.add_argument("--next-hop", help="Filter routes by next-hop IP address")
    parser.add_argument("--lookup", metavar="IP", help="Longest-prefix match lookup for a destination IP")
    parser.add_argument("--vrf", default="", help="VRF name (omit for global table)")
    parser.add_argument("--output", metavar="FILE", help="Save results as JSON to FILE")
    return parser.parse_args()


def main():
    args = parse_args()
    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    client = ssh_connect(args.device, args.username, password, port=args.port)

    vrf_clause = f" vrf {args.vrf}" if args.vrf else ""
    command = f"show ip route{vrf_clause}"
    logger.info("Running: %s", command)

    raw = run_command(client, command)
    client.close()

    routes = parse_routes(raw)
    logger.info("Parsed %d route entries", len(routes))

    if args.lookup:
        results = lookup_prefix(routes, args.lookup)
        title = f"LPM results for {args.lookup}"
    elif args.protocol:
        results = filter_by_protocol(routes, args.protocol)
        title = f"Routes via {args.protocol.upper()}"
    elif args.next_hop:
        results = filter_by_next_hop(routes, args.next_hop)
        title = f"Routes via next-hop {args.next_hop}"
    else:
        results = routes
        title = f"Full routing table — {args.device}"

    display_routes(results, title=title)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        logger.info("Results saved to %s", args.output)


if __name__ == "__main__":
    main()
```