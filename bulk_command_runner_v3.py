#!/usr/bin/env python3
"""
mac_address_table.py - Collect and display MAC address table from network switches.

Purpose:
    Connects to a Cisco IOS/IOS-XE switch via SSH and retrieves the MAC address
    table. Distinct from ARP table scripts: this shows L2 port-to-MAC mappings
    rather than IP-to-MAC bindings, making it useful for locating devices by
    MAC address, auditing port assignments, and troubleshooting L2 forwarding.

Usage:
    python mac_address_table.py -d 192.168.1.1 -u admin -p password
    python mac_address_table.py -d 192.168.1.1 -u admin --ask-pass
    python mac_address_table.py -d 192.168.1.1 -u admin -p password --vlan 10
    python mac_address_table.py -d 192.168.1.1 -u admin -p password --search Gi0/1
    python mac_address_table.py -d 192.168.1.1 -u admin -p password --output mac_table.csv

Prerequisites:
    pip install paramiko
    SSH access enabled on the target Cisco IOS/IOS-XE switch.
"""

import argparse
import csv
import getpass
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


def connect(host, username, password, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client, command, wait=1.5):
    chan = client.invoke_shell()
    chan.settimeout(10)
    time.sleep(0.5)
    chan.recv(4096)  # discard banner/prompt
    chan.send("terminal length 0\n")
    time.sleep(0.3)
    chan.recv(4096)
    chan.send(f"{command}\n")
    time.sleep(wait)
    output = ""
    while chan.recv_ready():
        output += chan.recv(65535).decode("utf-8", errors="replace")
    chan.close()
    return output


def parse_mac_table(raw):
    """Parse Cisco IOS 'show mac address-table' output into structured records."""
    entries = []
    # Matches lines like:  10   aabb.ccdd.eeff   DYNAMIC   Gi0/1
    pattern = re.compile(
        r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\w+)\s+(\S+)",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in pattern.finditer(raw):
        vlan, mac, entry_type, port = m.groups()
        hex_only = mac.replace(".", "")
        normalized = ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))
        entries.append({
            "vlan": vlan,
            "mac": normalized.lower(),
            "type": entry_type.upper(),
            "port": port,
        })
    return entries


def filter_entries(entries, vlan=None, search=None):
    if vlan is not None:
        entries = [e for e in entries if e["vlan"] == str(vlan)]
    if search:
        needle = search.lower().replace(":", "").replace(".", "").replace("-", "")
        entries = [
            e for e in entries
            if needle in e["mac"].replace(":", "")
            or needle in e["port"].lower()
        ]
    return entries


def print_table(entries):
    if not entries:
        print("No entries found.")
        return
    col_widths = {"vlan": 6, "mac": 20, "type": 10, "port": 20}
    header = (
        f"{'VLAN':<{col_widths['vlan']}} "
        f"{'MAC Address':<{col_widths['mac']}} "
        f"{'Type':<{col_widths['type']}} "
        f"Port"
    )
    print(header)
    print("-" * (len(header) + 4))
    for e in entries:
        print(
            f"{e['vlan']:<{col_widths['vlan']}} "
            f"{e['mac']:<{col_widths['mac']}} "
            f"{e['type']:<{col_widths['type']}} "
            f"{e['port']}"
        )
    print(f"\nTotal: {len(entries)} {'entry' if len(entries) == 1 else 'entries'}")


def write_csv(entries, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["vlan", "mac", "type", "port"])
        writer.writeheader()
        writer.writerows(entries)
    log.info("Wrote %d entries to %s", len(entries), path)


def build_parser():
    p = argparse.ArgumentParser(
        description="Collect and filter MAC address table from a Cisco switch via SSH"
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password")
    p.add_argument("--ask-pass", action="store_true", help="Prompt interactively for password")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--vlan", type=int, help="Show only entries for this VLAN")
    p.add_argument("--search", help="Filter by partial MAC address or port name")
    p.add_argument("--output", metavar="FILE", help="Write results to a CSV file")
    p.add_argument("--timeout", type=int, default=10, help="SSH connection timeout in seconds")
    p.add_argument("--debug", action="store_true", help="Enable debug-level logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")
    if not password:
        parser.error("Provide --password or --ask-pass")

    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = connect(args.device, args.username, password, args.port, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection to %s failed: %s", args.device, exc)
        sys.exit(1)

    try:
        log.info("Retrieving MAC address table")
        raw = run_command(client, "show mac address-table")
    except Exception as exc:
        log.error("Command execution failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    entries = parse_mac_table(raw)
    if not entries:
        log.warning("No MAC table entries parsed — verify device type and access level")

    entries = filter_entries(entries, vlan=args.vlan, search=args.search)
    print_table(entries)

    if args.output:
        try:
            write_csv(entries, args.output)
        except OSError as exc:
            log.error("Failed to write CSV: %s", exc)
            sys.exit(1)