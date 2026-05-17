#!/usr/bin/env python3
"""
mac_address_table.py - Retrieve and filter the MAC address table from Cisco switches.

Purpose:
    Connects to a Cisco IOS/IOS-XE switch via SSH (paramiko) and collects the MAC
    address table. Supports filtering by VLAN, interface, or partial MAC address for
    targeted L2 lookups. Useful for port-to-device mapping, security audits, and
    troubleshooting unknown unicast flooding.

Usage:
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret --vlan 100
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret --mac aa:bb:cc
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret --interface Gi0/1
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret --output table.csv

Prerequisites:
    pip install paramiko
    SSH enabled on target switch: ip ssh version 2
    User requires privilege level 1 or higher.
"""

from __future__ import annotations

import argparse
import csv
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# Matches Cisco dotted-hex MAC format: vlan  mac  type  interface
_MAC_LINE_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
    r"(\w+)\s+"
    r"(\S+)",
    re.IGNORECASE,
)


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client: paramiko.SSHClient, command: str) -> str:
    shell = client.invoke_shell()
    shell.settimeout(30)
    time.sleep(1)
    shell.recv(4096)  # discard login banner/prompt
    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(4096)
    shell.send(f"{command}\n")
    time.sleep(2)
    buf = b""
    while shell.recv_ready():
        buf += shell.recv(65535)
    shell.close()
    return buf.decode("utf-8", errors="replace")


def _normalize_mac(cisco_mac: str) -> str:
    """Convert Cisco dotted-hex (aabb.ccdd.eeff) to colon-separated."""
    flat = cisco_mac.replace(".", "")
    return ":".join(flat[i : i + 2] for i in range(0, 12, 2))


def parse_mac_table(raw: str) -> list[dict]:
    entries = []
    for line in raw.splitlines():
        match = _MAC_LINE_RE.match(line)
        if not match:
            continue
        vlan, mac, entry_type, interface = match.groups()
        entries.append(
            {
                "vlan": int(vlan),
                "mac": _normalize_mac(mac),
                "type": entry_type.upper(),
                "interface": interface,
            }
        )
    return entries


def filter_entries(
    entries: list[dict],
    vlan: int | None,
    mac_filter: str | None,
    iface_filter: str | None,
) -> list[dict]:
    result = entries
    if vlan is not None:
        result = [e for e in result if e["vlan"] == vlan]
    if mac_filter:
        needle = mac_filter.lower().replace("-", "").replace(":", "").replace(".", "")
        result = [e for e in result if needle in e["mac"].replace(":", "")]
    if iface_filter:
        needle = iface_filter.lower()
        result = [e for e in result if needle in e["interface"].lower()]
    return result


def print_table(entries: list[dict]) -> None:
    if not entries:
        print("No matching MAC address table entries found.")
        return
    print(f"{'VLAN':<8} {'MAC Address':<20} {'Type':<10} Interface")
    print("-" * 62)
    for e in entries:
        print(f"{e['vlan']:<8} {e['mac']:<20} {e['type']:<10} {e['interface']}")
    print(f"\n{len(entries)} entries")


def write_csv(entries: list[dict], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["vlan", "mac", "type", "interface"])
        writer.writeheader()
        writer.writerows(entries)
    logger.info("Wrote %d entries to %s", len(entries), path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Retrieve and filter the MAC address table from a Cisco switch."
    )
    parser.add_argument("-d", "--device", required=True, help="Switch IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vlan", type=int, help="Filter results to this VLAN ID")
    parser.add_argument("--mac", help="Filter by partial MAC (any separator or none)")
    parser.add_argument("--interface", help="Filter by interface name (partial match)")
    parser.add_argument("--output", help="Write results to a CSV file instead of stdout")
    args = parser.parse_args()

    try:
        logger.info("Connecting to %s:%d", args.device, args.port)
        client = connect(args.device, args.port, args.username, args.password)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for user '%s'", args.username)
        sys.exit(1)
    except Exception as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        raw = run_command(client, "show mac address-table")
    except Exception as exc:
        logger.error("Failed to retrieve MAC address table: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    entries = parse_mac_table(raw)
    if not entries:
        logger.warning(
            "No entries parsed — confirm device is Cisco IOS/IOS-XE and SSH output is clean"
        )
        sys.exit(0)

    logger.info("Parsed %d total MAC entries", len(entries))
    entries = filter_entries(entries, args.vlan, args.mac, args.interface)

    if args.output:
        write_csv(entries, args.output)
    else:
        print_table(entries)


if __name__ == "__main__":
    main()