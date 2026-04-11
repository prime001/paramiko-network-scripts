```python
"""
arp_table.py - ARP Table Retrieval and Analysis Tool

Connects to network devices via SSH and retrieves the ARP table, then parses
and displays results in human-readable or JSON format. Supports filtering by
IP prefix, MAC OUI, or interface, and can flag duplicate IPs (potential
IP conflicts) or duplicate MACs (potential MAC spoofing).

Usage:
    python arp_table.py -d 192.168.1.1 -u admin -p secret
    python arp_table.py -d 10.0.0.1 -u admin --filter-ip 10.1.0 --format json
    python arp_table.py -d 192.168.1.1 -u admin --filter-iface GigabitEthernet0/1
    python arp_table.py -d 10.0.0.1 -u admin --check-duplicates

Prerequisites:
    pip install paramiko
    Device must be reachable via SSH with appropriate credentials.
    Account requires privilege level sufficient to run 'show arp'.
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class ArpEntry:
    protocol: str
    ip_address: str
    age: str
    mac_address: str
    entry_type: str
    interface: str


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
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
        log.info("Connected to %s:%d", host, port)
        return client
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", host, exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Network error connecting to %s: %s", host, exc)
        sys.exit(1)


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.warning("stderr: %s", err)
        return output
    except paramiko.SSHException as exc:
        log.error("Command execution failed: %s", exc)
        sys.exit(1)


def parse_arp_table(raw: str) -> List[ArpEntry]:
    """Parse Cisco IOS-style 'show arp' output into structured entries."""
    entries: List[ArpEntry] = []
    # Pattern: Protocol  Address  Age(min)  Hardware Addr  Type  Interface
    pattern = re.compile(
        r"^(\S+)\s+([\d.]+)\s+(\d+|-)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|-)\s+(\S+)\s+(\S+)",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in pattern.finditer(raw):
        entries.append(
            ArpEntry(
                protocol=match.group(1),
                ip_address=match.group(2),
                age=match.group(3),
                mac_address=match.group(4).lower(),
                entry_type=match.group(5),
                interface=match.group(6),
            )
        )
    return entries


def filter_entries(
    entries: List[ArpEntry],
    filter_ip: Optional[str],
    filter_iface: Optional[str],
    filter_mac: Optional[str],
) -> List[ArpEntry]:
    if filter_ip:
        entries = [e for e in entries if e.ip_address.startswith(filter_ip)]
    if filter_iface:
        entries = [e for e in entries if filter_iface.lower() in e.interface.lower()]
    if filter_mac:
        oui = filter_mac.lower().replace(":", "").replace("-", "")
        entries = [e for e in entries if e.mac_address.replace(".", "").startswith(oui)]
    return entries


def check_duplicates(entries: List[ArpEntry]) -> None:
    from collections import defaultdict

    ip_map: dict = defaultdict(list)
    mac_map: dict = defaultdict(list)
    for e in entries:
        ip_map[e.ip_address].append(e.mac_address)
        if e.mac_address != "-":
            mac_map[e.mac_address].append(e.ip_address)

    found = False
    for ip, macs in ip_map.items():
        if len(macs) > 1:
            log.warning("DUPLICATE IP %s -> MACs: %s", ip, ", ".join(macs))
            found = True
    for mac, ips in mac_map.items():
        if len(ips) > 1:
            log.warning("DUPLICATE MAC %s -> IPs: %s", mac, ", ".join(ips))
            found = True
    if not found:
        log.info("No duplicate IPs or MACs detected.")


def print_table(entries: List[ArpEntry]) -> None:
    if not entries:
        print("No ARP entries found.")
        return
    header = f"{'Protocol':<10} {'IP Address':<18} {'Age':>5} {'MAC Address':<18} {'Type':<8} {'Interface'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(f"{e.protocol:<10} {e.ip_address:<18} {e.age:>5} {e.mac_address:<18} {e.entry_type:<8} {e.interface}")
    print(f"\nTotal entries: {len(entries)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze ARP table from a network device via SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--filter-ip", metavar="PREFIX", help="Filter by IP prefix (e.g. 10.1.0)")
    parser.add_argument("--filter-iface", metavar="IFACE", help="Filter by interface name substring")
    parser.add_argument("--filter-mac", metavar="OUI", help="Filter by MAC OUI prefix (e.g. 00:1a:2b)")
    parser.add_argument("--check-duplicates", action="store_true", help="Warn on duplicate IPs or MACs")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    client = ssh_connect(args.device, args.username, password, args.port)
    try:
        raw = run_command(client, "show arp")
    finally:
        client.close()

    if not raw.strip():
        log.error("Empty response from device. Check credentials and privilege level.")
        sys.exit(1)

    entries = parse_arp_table(raw)
    log.info("Parsed %d ARP entries", len(entries))

    entries = filter_entries(entries, args.filter_ip, args.filter_iface, args.filter_mac)

    if args.check_duplicates:
        check_duplicates(entries)

    if args.format == "json":
        print(json.dumps([asdict(e) for e in entries], indent=2))
    else:
        print_table(entries)


if __name__ == "__main__":
    main()
```