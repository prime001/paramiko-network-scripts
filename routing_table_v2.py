```python
"""
routing_table_analyzer.py - Network Device Routing Table Analyzer

Purpose:
    Connects to network devices via SSH, retrieves the routing table,
    parses routes by protocol, and exports structured data to JSON/CSV.
    Supports filtering by protocol or destination prefix, and baseline
    comparison to detect route changes over time.

Usage:
    python routing_table_analyzer.py -d 192.168.1.1 -u admin -p secret
    python routing_table_analyzer.py -d 10.0.0.1 -u admin --protocol ospf --export routes.json
    python routing_table_analyzer.py -d 10.0.0.1 -u admin --baseline baseline.json --compare

Prerequisites:
    pip install paramiko
    SSH access to target device (Cisco IOS/IOS-XE/NX-OS)
"""

import argparse
import csv
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

PROTOCOL_MAP = {
    "C": "connected", "S": "static", "R": "rip",
    "O": "ospf", "B": "bgp", "D": "eigrp",
    "i": "isis", "E": "eigrp-external", "IA": "ospf-inter-area",
    "E1": "ospf-ext1", "E2": "ospf-ext2", "N1": "nssa1", "N2": "nssa2",
}

ROUTE_PATTERN = re.compile(
    r"^([A-Z]{1,2}[*\s]?)\s+"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)"
    r"(?:\s+\[(\d+)/(\d+)\])?"
    r"(?:\s+via\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?"
    r"(?:,\s+[\w:]+)?"
    r"(?:,\s+(\S+))?",
    re.MULTILINE,
)


@dataclass
class Route:
    protocol: str
    prefix: str
    admin_distance: Optional[int]
    metric: Optional[int]
    next_hop: Optional[str]
    interface: Optional[str]


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.Channel:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    logger.info("Connecting to %s:%d", host, port)
    client.connect(host, port=port, username=username, password=password,
                   look_for_keys=False, allow_agent=False, timeout=15)
    channel = client.invoke_shell()
    channel.settimeout(20)
    _flush(channel)
    return channel


def _flush(channel: paramiko.Channel, wait: float = 1.5) -> str:
    import time
    time.sleep(wait)
    output = ""
    while channel.recv_ready():
        output += channel.recv(65535).decode("utf-8", errors="replace")
    return output


def send_command(channel: paramiko.Channel, command: str) -> str:
    channel.send(command + "\n")
    output = _flush(channel, wait=2.0)
    # Handle --More-- pagination
    while "More" in output or "--more--" in output.lower():
        channel.send(" ")
        chunk = _flush(channel, wait=1.0)
        output = output.replace("--More--", "").replace("--more--", "") + chunk
    return output


def parse_routes(raw_output: str) -> list[Route]:
    routes = []
    for match in ROUTE_PATTERN.finditer(raw_output):
        proto_code = match.group(1).strip().rstrip("*").strip()
        protocol = PROTOCOL_MAP.get(proto_code, proto_code.lower() or "unknown")
        prefix = match.group(2)
        ad = int(match.group(3)) if match.group(3) else None
        metric = int(match.group(4)) if match.group(4) else None
        next_hop = match.group(5)
        interface = match.group(6)
        routes.append(Route(protocol, prefix, ad, metric, next_hop, interface))
    return routes


def filter_routes(routes: list[Route], protocol: Optional[str], prefix: Optional[str]) -> list[Route]:
    if protocol:
        routes = [r for r in routes if protocol.lower() in r.protocol.lower()]
    if prefix:
        routes = [r for r in routes if r.prefix.startswith(prefix)]
    return routes


def compare_to_baseline(current: list[Route], baseline_path: str) -> None:
    try:
        with open(baseline_path) as f:
            baseline_data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load baseline: %s", exc)
        return

    baseline_prefixes = {r["prefix"] for r in baseline_data.get("routes", [])}
    current_prefixes = {r.prefix for r in current}

    added = current_prefixes - baseline_prefixes
    removed = baseline_prefixes - current_prefixes

    if not added and not removed:
        logger.info("No route changes detected vs baseline.")
    else:
        if added:
            logger.warning("NEW routes not in baseline: %s", ", ".join(sorted(added)))
        if removed:
            logger.warning("MISSING routes from baseline: %s", ", ".join(sorted(removed)))


def export_routes(routes: list[Route], path: str, host: str) -> None:
    payload = {
        "host": host,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "route_count": len(routes),
        "routes": [asdict(r) for r in routes],
    }
    if path.endswith(".csv"):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(asdict(routes[0]).keys()) if routes else [])
            writer.writeheader()
            writer.writerows(asdict(r) for r in routes)
    else:
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
    logger.info("Exported %d routes to %s", len(routes), path)


def print_summary(routes: list[Route]) -> None:
    from collections import Counter
    counts = Counter(r.protocol for r in routes)
    print(f"\n{'Protocol':<20} {'Count':>6}")
    print("-" * 28)
    for proto, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"{proto:<20} {count:>6}")
    print(f"\nTotal routes: {len(routes)}\n")

    for route in routes[:20]:
        nh = route.next_hop or "directly connected"
        intf = f" ({route.interface})" if route.interface else ""
        print(f"  [{route.protocol:<12}] {route.prefix:<22} via {nh}{intf}")
    if len(routes) > 20:
        print(f"  ... and {len(routes) - 20} more routes")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze routing tables from network devices."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--protocol", help="Filter routes by protocol (e.g. ospf, bgp, static)")
    parser.add_argument("--prefix", help="Filter routes by destination prefix (e.g. 10.0)")
    parser.add_argument("--export", metavar="FILE", help="Export results to JSON or CSV file")
    parser.add_argument("--baseline", metavar="FILE", help="Baseline JSON file for change comparison")
    parser.add_argument("--compare", action="store_true", help="Compare current table to baseline")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.password is None:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        channel = ssh_connect(args.device, args.username, args.password, args.port)
        send_command(channel, "terminal length 0")
        raw = send_command(channel, "show ip route")
        channel.close()
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    routes = parse_routes(raw)
    if not routes:
        logger.warning("No routes parsed. Check device output format.")

    routes = filter_routes(routes, args.protocol, args.prefix)
    logger.info("Found %d routes after filtering", len(routes))

    print_summary(routes)

    if args.export and routes:
        export_routes(routes, args.export, args.device)

    if args.compare and args.baseline:
        compare_to_baseline(routes, args.baseline)
    elif args.compare and not args.baseline:
        logger.error("--compare requires --baseline <file>")
        sys.exit(1)


if __name__ == "__main__":
    main()
```