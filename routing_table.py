```python
"""
routing_table.py — Routing Table Analyzer

Purpose:
    Connects to a network device via SSH, retrieves the routing table,
    parses route entries, and outputs a structured summary. Supports
    filtering by protocol, prefix, or next-hop, and can export results
    to JSON or CSV for further analysis.

Usage:
    python routing_table.py -d 192.168.1.1 -u admin -p secret
    python routing_table.py -d 192.168.1.1 -u admin --ask-pass --protocol ospf
    python routing_table.py -d 192.168.1.1 -u admin -p secret --prefix 10.0.0.0 --export json

Prerequisites:
    pip install paramiko
    Target device must support 'show ip route' (Cisco IOS/IOS-XE syntax).
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys
from io import StringIO

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

PROTOCOL_MAP = {
    "C": "connected",
    "S": "static",
    "R": "rip",
    "O": "ospf",
    "B": "bgp",
    "D": "eigrp",
    "i": "isis",
    "L": "local",
}

ROUTE_PATTERN = re.compile(
    r"^([A-Za-z*]+)\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)"
    r"(?:\s+\[(\d+)/(\d+)\])?"
    r"(?:\s+via\s+(\d{1,3}(?:\.\d{1,3}){3}))?"
    r"(?:,\s+(\S+))?"
)


def ssh_connect(host, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        log.info("Connected to %s:%s", host, port)
        return client
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)


def run_command(client, command, timeout=30):
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.warning("stderr: %s", err)
        return output
    except paramiko.SSHException as exc:
        log.error("Command execution failed: %s", exc)
        return ""


def parse_routes(raw_output):
    routes = []
    for line in raw_output.splitlines():
        line = line.rstrip()
        if not line or line.startswith("Codes") or line.startswith("Gateway"):
            continue
        match = ROUTE_PATTERN.match(line)
        if not match:
            continue
        code_raw, prefix, ad, metric, via, iface = match.groups()
        code = code_raw.lstrip("*+ ")[0] if code_raw.strip() else ""
        protocol = PROTOCOL_MAP.get(code, code)
        routes.append(
            {
                "prefix": prefix,
                "protocol": protocol,
                "code": code,
                "admin_distance": int(ad) if ad else None,
                "metric": int(metric) if metric else None,
                "next_hop": via or "directly connected",
                "interface": iface or "",
            }
        )
    return routes


def filter_routes(routes, protocol=None, prefix_filter=None, next_hop=None):
    filtered = routes
    if protocol:
        proto_lower = protocol.lower()
        filtered = [r for r in filtered if r["protocol"].lower() == proto_lower]
    if prefix_filter:
        filtered = [r for r in filtered if r["prefix"].startswith(prefix_filter)]
    if next_hop:
        filtered = [r for r in filtered if next_hop in r["next_hop"]]
    return filtered


def print_table(routes):
    if not routes:
        print("No routes matched.")
        return
    header = f"{'PREFIX':<22} {'PROTO':<12} {'AD/METRIC':<12} {'NEXT-HOP':<18} {'IFACE'}"
    print(header)
    print("-" * len(header))
    for r in routes:
        ad_metric = (
            f"{r['admin_distance']}/{r['metric']}"
            if r["admin_distance"] is not None
            else "-"
        )
        print(
            f"{r['prefix']:<22} {r['protocol']:<12} {ad_metric:<12} "
            f"{r['next_hop']:<18} {r['interface']}"
        )
    print(f"\nTotal: {len(routes)} route(s)")


def export_json(routes, path):
    with open(path, "w") as fh:
        json.dump(routes, fh, indent=2)
    log.info("Exported JSON to %s", path)


def export_csv(routes, path):
    if not routes:
        return
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=routes[0].keys())
        writer.writeheader()
        writer.writerows(routes)
    log.info("Exported CSV to %s", path)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze routing table from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol",
        help="Filter by routing protocol (e.g. ospf, bgp, static)",
    )
    parser.add_argument("--prefix", help="Filter routes by prefix substring (e.g. 10.0)")
    parser.add_argument("--next-hop", help="Filter routes by next-hop IP substring")
    parser.add_argument(
        "--export",
        choices=["json", "csv"],
        help="Export results to file",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help="Output filename for export (auto-generated if omitted)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or not password:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    client = ssh_connect(args.device, args.port, args.username, password)
    try:
        raw = run_command(client, "show ip route")
    finally:
        client.close()

    if not raw:
        log.error("Empty output received — check device compatibility.")
        sys.exit(1)

    all_routes = parse_routes(raw)
    log.info("Parsed %d total routes", len(all_routes))

    routes = filter_routes(all_routes, args.protocol, args.prefix, args.next_hop)
    print_table(routes)

    if args.export:
        out_file = args.output_file or f"{args.device}_routes.{args.export}"
        if args.export == "json":
            export_json(routes, out_file)
        else:
            export_csv(routes, out_file)
```