"""
routing_table.py - Retrieve and parse routing tables from network devices via SSH.

Purpose:
    Connects to one or more network devices over SSH using Paramiko, retrieves
    the IP routing table, parses the output into structured records, and exports
    results as JSON, CSV, or plain text.

Usage:
    python routing_table.py -d 192.168.1.1 -u admin -p secret
    python routing_table.py -d 192.168.1.1 192.168.1.2 -u admin --ask-pass
    python routing_table.py -d 192.168.1.1 -u admin -p secret --vrf MGMT --format json

Prerequisites:
    pip install paramiko
    Target devices must have SSH enabled and the user must have privilege level
    sufficient to run 'show ip route' (Cisco IOS/IOS-XE assumed; adjust
    SHOW_CMD for other platforms).
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

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)
log = logging.getLogger(__name__)

SHOW_CMD = "show ip route"
CONNECT_TIMEOUT = 15
RECV_BUFFER = 65535

# Cisco IOS route line pattern
# e.g. "O     10.0.0.0/8 [110/20] via 192.168.1.1, 00:01:02, GigabitEthernet0/1"
ROUTE_RE = re.compile(
    r"^(?P<proto>[OSBDREICL*+]\s*\S*)\s+"
    r"(?P<network>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)"
    r"(?:\s+\[(?P<ad>\d+)/(?P<metric>\d+)\])?"
    r"(?:\s+via\s+(?P<nexthop>\d{1,3}(?:\.\d{1,3}){3}))?"
    r"(?:,\s+(?P<age>\S+))?"
    r"(?:,\s+(?P<interface>\S+))?",
    re.MULTILINE,
)


def ssh_connect(host, username, password, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=CONNECT_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client, command):
    channel = client.invoke_shell()
    channel.settimeout(CONNECT_TIMEOUT)
    # Drain banner
    while channel.recv_ready():
        channel.recv(RECV_BUFFER)
    channel.send(command + "\n")
    output = []
    while True:
        chunk = channel.recv(RECV_BUFFER).decode("utf-8", errors="replace")
        output.append(chunk)
        if re.search(r"[>#]\s*$", chunk):
            break
    channel.close()
    return "".join(output)


def parse_routes(raw_output):
    routes = []
    for match in ROUTE_RE.finditer(raw_output):
        routes.append({
            "protocol": match.group("proto").strip(),
            "network": match.group("network"),
            "admin_distance": match.group("ad") or "",
            "metric": match.group("metric") or "",
            "nexthop": match.group("nexthop") or "",
            "age": match.group("age") or "",
            "interface": match.group("interface") or "",
        })
    return routes


def fetch_routing_table(host, username, password, port, vrf=None):
    cmd = SHOW_CMD
    if vrf:
        cmd = f"show ip route vrf {vrf}"
    log.info("Connecting to %s:%s", host, port)
    try:
        client = ssh_connect(host, username, password, port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s", host)
        return host, None
    except Exception as exc:
        log.error("Cannot connect to %s: %s", host, exc)
        return host, None

    try:
        raw = run_command(client, cmd)
        routes = parse_routes(raw)
        log.info("Retrieved %d route entries from %s", len(routes), host)
        return host, routes
    except Exception as exc:
        log.error("Command execution failed on %s: %s", host, exc)
        return host, None
    finally:
        client.close()


def output_json(results):
    print(json.dumps(results, indent=2))


def output_csv(results):
    fields = ["host", "protocol", "network", "admin_distance",
              "metric", "nexthop", "age", "interface"]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields)
    writer.writeheader()
    for host, routes in results.items():
        if routes is None:
            continue
        for r in routes:
            r["host"] = host
            writer.writerow(r)


def output_text(results):
    for host, routes in results.items():
        print(f"\n{'='*60}")
        print(f"  Host: {host}")
        print(f"{'='*60}")
        if routes is None:
            print("  ERROR: Could not retrieve routing table.")
            continue
        fmt = "{:<10} {:<20} {:<6} {:<8} {:<16} {:<10} {}"
        print(fmt.format("Proto", "Network", "AD", "Metric",
                         "Next-Hop", "Age", "Interface"))
        print("-" * 80)
        for r in routes:
            print(fmt.format(
                r["protocol"][:10], r["network"], r["admin_distance"],
                r["metric"], r["nexthop"], r["age"], r["interface"],
            ))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Retrieve IP routing tables from network devices via SSH."
    )
    parser.add_argument("-d", "--devices", nargs="+", required=True,
                        metavar="HOST", help="Device hostname(s) or IP address(es)")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password")
    parser.add_argument("--ask-pass", action="store_true",
                        help="Prompt for password interactively")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", metavar="NAME", help="VRF name for VRF-specific table")
    parser.add_argument("--format", choices=["text", "json", "csv"],
                        default="text", dest="output_format",
                        help="Output format (default: text)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if args.ask_pass:
        password = getpass.getpass("SSH Password: ")
    elif args.password:
        password = args.password
    else:
        log.error("Provide --password or --ask-pass")
        sys.exit(1)

    results = {}
    for device in args.devices:
        host, routes = fetch_routing_table(
            device, args.username, password, args.port, vrf=args.vrf
        )
        results[host] = routes

    if args.output_format == "json":
        output_json(results)
    elif args.output_format == "csv":
        output_csv(results)
    else:
        output_text(results)

    failed = [h for h, r in results.items() if r is None]
    if failed:
        log.warning("Failed to retrieve data from: %s", ", ".join(failed))
        sys.exit(1)