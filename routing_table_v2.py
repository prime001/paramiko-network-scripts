```python
#!/usr/bin/env python3
"""
routing_table.py - Network Routing Table Collector

Connects to one or more network devices via SSH and retrieves the IP routing
table. Supports filtering by protocol (OSPF, BGP, static, connected) and
optional export to JSON or CSV for further analysis.

Usage:
    python routing_table.py -d 192.168.1.1 -u admin -p secret
    python routing_table.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa --protocol ospf
    python routing_table.py --hosts-file devices.txt -u admin -p secret --output routes.json

Prerequisites:
    pip install paramiko
    Network devices must have SSH enabled and the user must have privilege
    level sufficient to run 'show ip route' (IOS) or equivalent.
"""

import argparse
import csv
import json
import logging
import re
import sys
from getpass import getpass
from io import StringIO

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("routing_table")

PROTOCOL_MAP = {
    "C": "connected",
    "S": "static",
    "R": "rip",
    "O": "ospf",
    "B": "bgp",
    "D": "eigrp",
    "i": "isis",
    "L": "local",
    "E": "egp",
}

ROUTE_RE = re.compile(
    r"^(?P<proto>[A-Za-z*]+)\s+"
    r"(?P<network>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\s+"
    r"(?:\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+)?"
    r"(?:via\s+(?P<nexthop>\d{1,3}(?:\.\d{1,3}){3}))?"
    r"(?:.*,\s*(?P<iface>\S+))?",
    re.MULTILINE,
)


def ssh_connect(host, username, password=None, key_path=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        allow_agent=True,
        look_for_keys=True,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = False
    elif password:
        connect_kwargs["password"] = password
        connect_kwargs["look_for_keys"] = False

    client.connect(**connect_kwargs)
    return client


def run_command(client, command, timeout=30):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    if error.strip():
        logger.debug("stderr from device: %s", error.strip())
    return output


def parse_routes(raw_output, filter_protocol=None):
    routes = []
    for match in ROUTE_RE.finditer(raw_output):
        proto_code = match.group("proto").lstrip("*").strip()
        proto_name = PROTOCOL_MAP.get(proto_code, proto_code)

        if filter_protocol and proto_name != filter_protocol:
            continue

        routes.append(
            {
                "protocol": proto_name,
                "protocol_code": proto_code,
                "network": match.group("network"),
                "admin_distance": match.group("ad"),
                "metric": match.group("metric"),
                "next_hop": match.group("nexthop"),
                "interface": match.group("iface"),
            }
        )
    return routes


def collect_routes(host, username, password=None, key_path=None, port=22,
                   filter_protocol=None, vrf=None):
    logger.info("Connecting to %s:%s", host, port)
    try:
        client = ssh_connect(host, username, password=password,
                             key_path=key_path, port=port)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        return None
    except paramiko.SSHException as exc:
        logger.error("SSH error connecting to %s: %s", host, exc)
        return None
    except OSError as exc:
        logger.error("Network error connecting to %s: %s", host, exc)
        return None

    try:
        if vrf:
            command = f"show ip route vrf {vrf}"
        else:
            command = "show ip route"

        logger.info("Running '%s' on %s", command, host)
        raw = run_command(client, command)
        routes = parse_routes(raw, filter_protocol=filter_protocol)
        logger.info("Found %d route(s) on %s", len(routes), host)
        return {"host": host, "routes": routes, "raw": raw}
    except paramiko.SSHException as exc:
        logger.error("Command execution failed on %s: %s", host, exc)
        return None
    finally:
        client.close()


def export_json(results, path):
    with open(path, "w") as fh:
        json.dump(results, fh, indent=2)
    logger.info("Results written to %s", path)


def export_csv(results, path):
    fieldnames = ["host", "protocol", "network", "admin_distance",
                  "metric", "next_hop", "interface"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            host = result["host"]
            for route in result["routes"]:
                writer.writerow({
                    "host": host,
                    "protocol": route["protocol"],
                    "network": route["network"],
                    "admin_distance": route.get("admin_distance", ""),
                    "metric": route.get("metric", ""),
                    "next_hop": route.get("next_hop", ""),
                    "interface": route.get("interface", ""),
                })
    logger.info("Results written to %s", path)


def print_table(result):
    host = result["host"]
    routes = result["routes"]
    print(f"\n{'='*60}")
    print(f"Host: {host}  ({len(routes)} routes)")
    print(f"{'='*60}")
    print(f"{'Proto':<10} {'Network':<20} {'Next-Hop':<18} {'AD/Metric':<12} {'Interface'}")
    print(f"{'-'*10} {'-'*20} {'-'*18} {'-'*12} {'-'*15}")
    for r in routes:
        ad_metric = (f"{r['admin_distance']}/{r['metric']}"
                     if r.get("admin_distance") else "")
        print(
            f"{r['protocol']:<10} "
            f"{r['network'] or '':<20} "
            f"{r['next_hop'] or '':<18} "
            f"{ad_metric:<12} "
            f"{r['interface'] or ''}"
        )


def build_parser():
    parser = argparse.ArgumentParser(
        description="Retrieve and display IP routing tables from network devices.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("--hosts-file", metavar="FILE",
                        help="File with one host per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", metavar="PATH", dest="key_path",
                        help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--protocol", choices=list(PROTOCOL_MAP.values()),
                        help="Filter routes by protocol")
    parser.add_argument("--vrf", help="VRF name for 'show ip route vrf <name>'")
    parser.add_argument("--output", metavar="FILE",
                        help="Export results to file (.json or .csv)")
    parser.add_argument("--raw", action="store_true",
                        help="Print raw device output instead of parsed table")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if not args.key_path and not args.password:
        args.password = getpass(f"Password for {args.username}: ")

    if args.device:
        hosts = [args.device]
    else:
        try:
            with open(args.hosts_file) as fh:
                hosts = [line.strip() for line in fh if line.strip()
                         and not line.startswith("#")]
        except OSError as e:
            logger.error("Cannot read hosts file: %s", e)
            sys.exit(1)

    all_results = []
    for host in hosts:
        result = collect_routes(
            host,
            args.username,
            password=args.password,
            key_path=args.key_path,
            port=args.port,
            filter_protocol=args.protocol,
            vrf=args.vrf,
        )
        if result is None:
            continue
        all_results.append(result)

        if args.raw:
            print(f"\n--- {host} ---\n{result['raw']}")
        else:
            print_table(result)

    if not all_results:
        logger.error("No results collected; check connectivity and credentials.")
        sys.exit(1)

    if args.output:
        if args.output.endswith(".csv"):
            export_csv(all_results, args.output)
        else:
            export_json(all_results, args.output)

    sys.exit(0)
```