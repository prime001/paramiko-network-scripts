#!/usr/bin/env python3
"""
ARP Table Parser — 008_arp_table.py

Purpose:
    Connect to a Cisco IOS/IOS-XE device via SSH, retrieve the ARP table,
    and parse it into structured data for export or analysis.

Usage:
    python 008_arp_table.py -d 192.168.1.1 -u admin -p secret
    python 008_arp_table.py -d 192.168.1.1 -u admin --output json
    python 008_arp_table.py -d 192.168.1.1 -u admin --filter-iface Gi0/0
    python 008_arp_table.py -d 192.168.1.1 -u admin --output csv --outfile arp.csv

Prerequisites:
    pip install paramiko
    SSH access to a Cisco IOS/IOS-XE device.
    Credentials with at least privilege 1 (no 'enable' required for 'show arp').
"""

import argparse
import csv
import getpass
import io
import json
import logging
import re
import sys
import time

import paramiko

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)
log = logging.getLogger(__name__)

ARP_PATTERN = re.compile(
    r"^Internet\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<age>\d+|-)\s+"
    r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
    r"(?P<type>ARPA|Other)\s+"
    r"(?P<interface>\S+)",
    re.IGNORECASE | re.MULTILINE,
)


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info("Connecting to %s:%d as %s", host, port, username)
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


def run_command(client: paramiko.SSHClient, command: str, wait: float = 2.0) -> str:
    shell = client.invoke_shell(width=220, height=50)
    time.sleep(0.5)
    shell.recv(65535)  # drain banner/prompt

    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(65535)

    shell.send(command + "\n")
    time.sleep(wait)

    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.2)

    shell.close()
    return output


def parse_arp(raw: str, iface_filter: str | None = None) -> list[dict]:
    entries = []
    for match in ARP_PATTERN.finditer(raw):
        entry = match.groupdict()
        if iface_filter and iface_filter.lower() not in entry["interface"].lower():
            continue
        entries.append(entry)
    return entries


def output_table(entries: list[dict]) -> None:
    if not entries:
        print("No ARP entries found.")
        return
    header = f"{'IP Address':<18} {'Age':>5}  {'MAC Address':<16} {'Type':<6} {'Interface'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(
            f"{e['ip']:<18} {e['age']:>5}  {e['mac']:<16} {e['type']:<6} {e['interface']}"
        )
    print(f"\nTotal entries: {len(entries)}")


def output_json(entries: list[dict], outfile: str | None) -> None:
    data = json.dumps(entries, indent=2)
    if outfile:
        with open(outfile, "w") as fh:
            fh.write(data)
        log.info("JSON written to %s", outfile)
    else:
        print(data)


def output_csv(entries: list[dict], outfile: str | None) -> None:
    fields = ["ip", "age", "mac", "type", "interface"]
    dest = open(outfile, "w", newline="") if outfile else io.StringIO()
    writer = csv.DictWriter(dest, fieldnames=fields)
    writer.writeheader()
    writer.writerows(entries)
    if outfile:
        dest.close()
        log.info("CSV written to %s", outfile)
    else:
        print(dest.getvalue())


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse ARP table from a Cisco IOS/IOS-XE device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--outfile", default=None, help="Write output to file instead of stdout")
    parser.add_argument(
        "--filter-iface",
        metavar="IFACE",
        default=None,
        help="Filter results to entries on a specific interface (substring match)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = build_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = connect(args.device, args.port, args.username, password)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        log.info("Retrieving ARP table...")
        raw = run_command(client, "show arp")
        log.debug("Raw output:\n%s", raw)
    finally:
        client.close()

    entries = parse_arp(raw, iface_filter=args.filter_iface)
    log.info("Parsed %d ARP entries", len(entries))

    if args.output == "json":
        output_json(entries, args.outfile)
    elif args.output == "csv":
        output_csv(entries, args.outfile)
    else:
        output_table(entries)