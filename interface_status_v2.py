#!/usr/bin/env python3
"""
Interface Status Monitor - paramiko-network-scripts

Purpose:
    Connects to a Cisco IOS/IOS-XE device via SSH and retrieves the operational
    status of all interfaces (or a filtered subset). Outputs a formatted table
    showing interface name, line protocol status, IP address, speed, duplex, and
    description. Optionally writes results to CSV for reporting or trending.

Usage:
    python interface_status.py -H 192.168.1.1 -u admin -p secret
    python interface_status.py -H 192.168.1.1 -u admin -p secret --filter GigabitEthernet
    python interface_status.py -H 192.168.1.1 -u admin -p secret --down-only --csv report.csv

Prerequisites:
    - Python 3.8+
    - paramiko >= 3.0  (pip install paramiko)
    - SSH access to the target device
    - Account with at least 'show' privilege
"""

import argparse
import csv
import logging
import re
import sys
import time
from dataclasses import dataclass, fields
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceStatus:
    name: str
    status: str
    protocol: str
    ip_address: str
    speed: str
    duplex: str
    description: str


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    log.info("Connected to %s:%d", host, port)
    return client


def run_command(shell: paramiko.Channel, command: str, wait: float = 1.5) -> str:
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
    return output


def parse_interfaces(raw_brief: str, raw_detail: str) -> List[InterfaceStatus]:
    interfaces = {}

    # Parse 'show ip interface brief'
    brief_pattern = re.compile(
        r"^(\S+)\s+([\d.]+|unassigned)\s+\S+\s+\S+\s+(\S+)\s+(\S+)",
        re.MULTILINE,
    )
    for m in brief_pattern.finditer(raw_brief):
        name, ip, status, protocol = m.group(1), m.group(2), m.group(3), m.group(4)
        if name.lower() == "interface":
            continue
        interfaces[name] = InterfaceStatus(
            name=name,
            status=status,
            protocol=protocol,
            ip_address=ip if ip != "unassigned" else "",
            speed="",
            duplex="",
            description="",
        )

    # Parse 'show interfaces' for speed, duplex, description
    iface_blocks = re.split(r"\n(?=\S)", raw_detail)
    for block in iface_blocks:
        name_match = re.match(r"^(\S+) is", block)
        if not name_match:
            continue
        name = name_match.group(1)
        if name not in interfaces:
            continue

        speed_match = re.search(r"BW (\d+) Kbit", block)
        duplex_match = re.search(r"(\S+)-duplex", block, re.IGNORECASE)
        desc_match = re.search(r"Description:\s+(.+)", block)

        iface = interfaces[name]
        if speed_match:
            kbit = int(speed_match.group(1))
            iface.speed = f"{kbit // 1000}M" if kbit < 1_000_000 else f"{kbit // 1_000_000}G"
        if duplex_match:
            iface.duplex = duplex_match.group(1).lower()
        if desc_match:
            iface.description = desc_match.group(1).strip()

    return list(interfaces.values())


def print_table(interfaces: List[InterfaceStatus]) -> None:
    col_widths = [28, 6, 8, 16, 7, 7, 30]
    headers = ["Interface", "Status", "Protocol", "IP Address", "Speed", "Duplex", "Description"]
    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
    separator = "  ".join("-" * w for w in col_widths)
    print(fmt.format(*headers))
    print(separator)
    for iface in interfaces:
        row = [
            iface.name[:col_widths[0]],
            iface.status[:col_widths[1]],
            iface.protocol[:col_widths[2]],
            iface.ip_address[:col_widths[3]],
            iface.speed[:col_widths[4]],
            iface.duplex[:col_widths[5]],
            iface.description[:col_widths[6]],
        ]
        print(fmt.format(*row))
    print(f"\n{len(interfaces)} interface(s) shown.")


def write_csv(interfaces: List[InterfaceStatus], path: str) -> None:
    fieldnames = [f.name for f in fields(InterfaceStatus)]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for iface in interfaces:
            writer.writerow({f: getattr(iface, f) for f in fieldnames})
    log.info("CSV written to %s", path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrieve and display interface status from a Cisco IOS device.",
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--filter", metavar="PATTERN", help="Show only interfaces matching pattern")
    parser.add_argument("--down-only", action="store_true", help="Show only down interfaces")
    parser.add_argument("--csv", metavar="FILE", help="Write results to CSV file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    try:
        client = ssh_connect(args.host, args.username, args.password, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    try:
        shell = client.invoke_shell(width=200, height=500)
        time.sleep(1)
        shell.recv(65535)  # discard banner/MOTD

        run_command(shell, "terminal length 0", wait=0.5)
        log.info("Fetching interface brief...")
        raw_brief = run_command(shell, "show ip interface brief", wait=2.0)
        log.info("Fetching interface details...")
        raw_detail = run_command(shell, "show interfaces", wait=3.0)
    except paramiko.SSHException as exc:
        log.error("SSH error during command execution: %s", exc)
        return 1
    finally:
        client.close()

    interfaces = parse_interfaces(raw_brief, raw_detail)

    if args.filter:
        interfaces = [i for i in interfaces if args.filter.lower() in i.name.lower()]
    if args.down_only:
        interfaces = [i for i in interfaces if i.protocol.lower() == "down"]

    if not interfaces:
        print("No interfaces matched the specified criteria.")
        return 0

    interfaces.sort(key=lambda i: i.name)
    print_table(interfaces)

    if args.csv:
        write_csv(interfaces, args.csv)

    return 0


if __name__ == "__main__":
    sys.exit(main())