```python
"""
ARP Table Retrieval and Analysis Tool
======================================
Connects to a network device via SSH (paramiko) and retrieves the ARP table,
parsing entries into structured data for display, filtering, and export.

Usage:
    python 010_arp_table.py -d 192.168.1.1 -u admin -p secret
    python 010_arp_table.py -d 192.168.1.1 -u admin --ask-pass --filter 10.0.0
    python 010_arp_table.py -d 192.168.1.1 -u admin -p secret --export arp.csv
    python 010_arp_table.py -d 192.168.1.1 -u admin -p secret --vrf MGMT

Prerequisites:
    pip install paramiko
    SSH access to target device (Cisco IOS/IOS-XE/NX-OS)
    Credentials with privilege level sufficient to run 'show arp'
"""

import argparse
import csv
import getpass
import io
import logging
import re
import sys
from dataclasses import dataclass, fields
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

ARP_PATTERN = re.compile(
    r"^(?:Internet)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<age>[\d-]+)\s+"
    r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|Incomplete)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<interface>\S+)?",
    re.MULTILINE,
)


@dataclass
class ArpEntry:
    ip: str
    age: str
    mac: str
    entry_type: str
    interface: str


def connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info("Connecting to %s:%d", host, port)
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return client


def run_command(client: paramiko.SSHClient, command: str) -> str:
    log.debug("Running: %s", command)
    _, stdout, stderr = client.exec_command(command, timeout=30)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace").strip()
    if error:
        log.warning("stderr: %s", error)
    return output


def parse_arp(raw: str) -> List[ArpEntry]:
    entries = []
    for match in ARP_PATTERN.finditer(raw):
        entries.append(
            ArpEntry(
                ip=match.group("ip"),
                age=match.group("age"),
                mac=match.group("mac"),
                entry_type=match.group("type"),
                interface=match.group("interface") or "",
            )
        )
    return entries


def filter_entries(entries: List[ArpEntry], pattern: str) -> List[ArpEntry]:
    return [
        e for e in entries
        if pattern in e.ip or pattern in e.mac or pattern in e.interface
    ]


def print_table(entries: List[ArpEntry]) -> None:
    if not entries:
        print("No ARP entries found.")
        return
    header = f"{'IP Address':<18} {'Age':>6}  {'MAC Address':<16} {'Type':<10} {'Interface'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(f"{e.ip:<18} {e.age:>6}  {e.mac:<16} {e.entry_type:<10} {e.interface}")
    print(f"\nTotal entries: {len(entries)}")


def export_csv(entries: List[ArpEntry], path: str) -> None:
    column_names = [f.name for f in fields(ArpEntry)]
    with io.open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=column_names)
        writer.writeheader()
        for e in entries:
            writer.writerow(
                {
                    "ip": e.ip,
                    "age": e.age,
                    "mac": e.mac,
                    "entry_type": e.entry_type,
                    "interface": e.interface,
                }
            )
    log.info("Exported %d entries to %s", len(entries), path)


def build_command(vrf: Optional[str]) -> str:
    if vrf:
        return f"show arp vrf {vrf}"
    return "show arp"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze ARP table from a network device over SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument(
        "--ask-pass", action="store_true", help="Prompt for password interactively"
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--vrf", default=None, help="VRF name to query (omit for global table)"
    )
    parser.add_argument(
        "--filter",
        metavar="PATTERN",
        default=None,
        help="Filter results by IP, MAC, or interface substring",
    )
    parser.add_argument(
        "--export", metavar="FILE", default=None, help="Export results to CSV file"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if args.ask_pass:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")
    elif args.password:
        password = args.password
    else:
        log.error("Provide --password or --ask-pass")
        sys.exit(1)

    client: Optional[paramiko.SSHClient] = None
    try:
        client = connect(args.device, args.username, password, args.port)
        command = build_command(args.vrf)
        raw_output = run_command(client, command)
        log.debug("Raw output:\n%s", raw_output)

        entries = parse_arp(raw_output)
        if not entries:
            log.warning("No ARP entries parsed — output may be unparseable or empty.")
            print(raw_output)
            sys.exit(0)

        if args.filter:
            entries = filter_entries(entries, args.filter)
            log.info("Filter '%s' matched %d entries", args.filter, len(entries))

        print_table(entries)

        if args.export:
            export_csv(entries, args.export)

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)
    finally:
        if client:
            client.close()
            log.debug("SSH connection closed")
```