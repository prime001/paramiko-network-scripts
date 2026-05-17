```python
#!/usr/bin/env python3
"""
mac_table.py - MAC Address Table Parser

Retrieves and parses the MAC address table from a Cisco IOS/IOS-XE switch
via SSH, outputting structured data for audit, troubleshooting, or CMDB feeds.
Distinct from arp_table.py (layer 3 IP-to-MAC) — this targets layer 2
switch port-to-MAC mappings.

Usage:
    python mac_table.py -d 192.168.1.1 -u admin
    python mac_table.py -d 192.168.1.1 -u admin --vlan 100 --format csv
    python mac_table.py -d 192.168.1.1 -u admin --interface Gi0/1 --format json

Prerequisites:
    pip install paramiko
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
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection to %s failed: %s", host, exc)
        sys.exit(1)
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def parse_mac_table(raw: str) -> list[dict]:
    entries = []
    # Matches IOS/IOS-XE format: VLAN  MAC  Type  Ports
    # e.g.:  100  aabb.cc00.1234  DYNAMIC     Gi0/1
    pattern = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(\S+)\s+"
        r"(\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(raw):
        vlan, mac, entry_type, port = match.groups()
        entries.append({
            "vlan": int(vlan),
            "mac": mac.lower(),
            "type": entry_type.upper(),
            "port": port,
        })
    return entries


def filter_entries(
    entries: list[dict],
    vlan: int | None = None,
    mac: str | None = None,
    port: str | None = None,
) -> list[dict]:
    if vlan is not None:
        entries = [e for e in entries if e["vlan"] == vlan]
    if mac:
        needle = mac.lower()
        entries = [e for e in entries if needle in e["mac"]]
    if port:
        needle = port.lower()
        entries = [e for e in entries if needle in e["port"].lower()]
    return entries


def render_table(entries: list[dict]) -> str:
    if not entries:
        return "No entries found."
    header = f"{'VLAN':<6} {'MAC Address':<18} {'Type':<10} Port"
    sep = "-" * 55
    rows = [header, sep]
    for e in entries:
        rows.append(f"{e['vlan']:<6} {e['mac']:<18} {e['type']:<10} {e['port']}")
    rows.append(sep)
    rows.append(f"Total: {len(entries)} entries")
    return "\n".join(rows)


def render_csv(entries: list[dict]) -> str:
    if not entries:
        return ""
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=["vlan", "mac", "type", "port"])
    writer.writeheader()
    writer.writerows(entries)
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser(
        description="Parse MAC address table from a network switch"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vlan", type=int, help="Filter by VLAN ID")
    parser.add_argument("--mac", help="Filter by MAC address substring (e.g. aabb.cc)")
    parser.add_argument("--interface", help="Filter by port/interface name substring")
    parser.add_argument(
        "--format",
        choices=["table", "csv", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    log.info("Connecting to %s", args.device)
    client = ssh_connect(args.device, args.username, password, args.port)

    try:
        log.info("Retrieving MAC address table")
        raw = run_command(client, "show mac address-table")
        if not raw.strip() or "Invalid input" in raw:
            log.debug("Retrying with 'dynamic' keyword (NX-OS fallback)")
            raw = run_command(client, "show mac address-table dynamic")
    finally:
        client.close()

    entries = parse_mac_table(raw)
    log.info("Parsed %d total MAC entries", len(entries))

    entries = filter_entries(entries, vlan=args.vlan, mac=args.mac, port=args.interface)
    log.info("%d entries after filtering", len(entries))

    if args.format == "json":
        print(json.dumps(entries, indent=2))
    elif args.format == "csv":
        print(render_csv(entries), end="")
    else:
        print(render_table(entries))


if __name__ == "__main__":
    main()
```