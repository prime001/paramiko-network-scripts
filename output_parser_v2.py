```python
"""
mac_table_parser.py - Cisco Switch MAC Address Table Parser

Purpose:
    Connects to a Cisco IOS/IOS-XE switch via SSH, retrieves the MAC address
    table, parses it into structured data, and exports results as JSON or CSV.
    Useful for network audits, rogue device detection, and port mapping.

Usage:
    python mac_table_parser.py -d 192.168.1.1 -u admin -p secret
    python mac_table_parser.py -d 192.168.1.1 -u admin -p secret --vlan 10 --format csv -o mac_table.csv

Prerequisites:
    pip install paramiko
    SSH access enabled on target device (ip ssh version 2)
"""

import argparse
import csv
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

MAC_PATTERN = re.compile(
    r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
    r"(DYNAMIC|STATIC|dynamic|static)\s+(\S+)",
    re.MULTILINE,
)


def connect(host, username, password, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        log.info("Connected to %s:%d", host, port)
        return client
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection to %s failed: %s", host, exc)
        sys.exit(1)


def run_command(client, command, wait=2.0):
    shell = client.invoke_shell()
    shell.settimeout(10)
    time.sleep(0.5)
    shell.recv(4096)  # drain banner/prompt

    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(4096)

    shell.send(command + "\n")
    time.sleep(wait)

    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.2)

    shell.close()
    return output


def parse_mac_table(raw_output):
    entries = []
    for match in MAC_PATTERN.finditer(raw_output):
        entries.append(
            {
                "vlan": int(match.group(1)),
                "mac_address": match.group(2),
                "type": match.group(3).upper(),
                "interface": match.group(4),
            }
        )
    return entries


def filter_by_vlan(entries, vlan_id):
    return [e for e in entries if e["vlan"] == vlan_id]


def write_json(entries, path):
    with open(path, "w") as fh:
        json.dump(entries, fh, indent=2)
    log.info("JSON output written to %s (%d entries)", path, len(entries))


def write_csv(entries, path):
    if not entries:
        log.warning("No entries to write")
        return
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["vlan", "mac_address", "type", "interface"])
        writer.writeheader()
        writer.writerows(entries)
    log.info("CSV output written to %s (%d entries)", path, len(entries))


def print_table(entries):
    if not entries:
        print("No MAC address entries found.")
        return
    header = f"{'VLAN':<6} {'MAC Address':<18} {'Type':<8} {'Interface'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(f"{e['vlan']:<6} {e['mac_address']:<18} {e['type']:<8} {e['interface']}")
    print(f"\nTotal entries: {len(entries)}")


def build_args():
    parser = argparse.ArgumentParser(
        description="Parse MAC address table from Cisco IOS/IOS-XE switch"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vlan", type=int, help="Filter results to a specific VLAN ID")
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("-o", "--output", help="Output file path (required for json/csv)")
    return parser.parse_args()


if __name__ == "__main__":
    args = build_args()

    if args.format in ("json", "csv") and not args.output:
        log.error("--output is required when using --format %s", args.format)
        sys.exit(1)

    client = connect(args.device, args.username, args.password, args.port)
    try:
        log.info("Retrieving MAC address table from %s", args.device)
        raw = run_command(client, "show mac address-table")
    finally:
        client.close()

    entries = parse_mac_table(raw)
    log.info("Parsed %d MAC address entries", len(entries))

    if args.vlan:
        entries = filter_by_vlan(entries, args.vlan)
        log.info("Filtered to VLAN %d: %d entries", args.vlan, len(entries))

    if args.format == "json":
        write_json(entries, args.output)
    elif args.format == "csv":
        write_csv(entries, args.output)
    else:
        print_table(entries)
```