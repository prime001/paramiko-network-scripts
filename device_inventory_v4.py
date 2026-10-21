#!/usr/bin/env python3
"""
vlan_inventory.py - Collect VLAN membership and port-assignment inventory from Cisco IOS switches.

Purpose:
    Connects to a Cisco IOS/IOS-XE switch via SSH and extracts the complete VLAN
    database: VLAN IDs, names, operational states, and assigned access ports.
    Useful for auditing VLAN configurations, validating port assignments, and
    generating switch documentation.

Usage:
    python vlan_inventory.py -H 192.168.1.1 -u admin
    python vlan_inventory.py -H 192.168.1.1 -u admin -p secret --csv vlans.csv
    python vlan_inventory.py -H 192.168.1.1 -u admin --show-inactive --debug

Prerequisites:
    - paramiko >= 2.0:  pip install paramiko
    - Target must be a Cisco IOS/IOS-XE switch with SSH enabled
    - User needs at minimum privilege 1 (show commands only)
"""

import argparse
import csv
import getpass
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def send_command(shell, command, wait=2.0, buf=65535):
    shell.send(command + "\n")
    time.sleep(wait)
    chunks = []
    while shell.recv_ready():
        chunks.append(shell.recv(buf).decode("utf-8", errors="replace"))
    return "".join(chunks)


def parse_vlan_brief(raw):
    """Return list of dicts from 'show vlan brief' output."""
    vlans = []
    lines = raw.splitlines()
    merged = []
    for line in lines:
        if re.match(r"^\d+\s+\S+\s+\S+", line):
            merged.append(line)
        elif merged and re.match(r"^\s{32,}\S", line):
            merged[-1] += ", " + line.strip()

    row_re = re.compile(
        r"^(\d+)\s+(\S+)\s+(active|act/lshut|act/unsup|unsupported|suspended|sus/lshut)\s*(.*)"
    )
    for line in merged:
        m = row_re.match(line)
        if not m:
            continue
        ports_raw = m.group(4).strip()
        ports = [p.strip() for p in ports_raw.split(",") if p.strip()] if ports_raw else []
        vlans.append(
            {
                "vlan_id": int(m.group(1)),
                "name": m.group(2),
                "status": m.group(3),
                "port_count": len(ports),
                "ports": ports,
            }
        )
    return vlans


def display_table(vlans):
    print(f"\n{'VLAN':>6}  {'Name':<24}  {'Status':<14}  {'Ports':>5}  Interfaces")
    print("-" * 85)
    for v in vlans:
        preview = ", ".join(v["ports"][:5])
        if len(v["ports"]) > 5:
            preview += f"  (+{len(v['ports']) - 5} more)"
        print(
            f"{v['vlan_id']:>6}  {v['name']:<24}  {v['status']:<14}  "
            f"{v['port_count']:>5}  {preview}"
        )
    print(f"\nTotal: {len(vlans)} VLANs\n")


def write_csv(vlans, path):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["vlan_id", "name", "status", "port_count", "ports"]
        )
        writer.writeheader()
        for v in vlans:
            row = dict(v)
            row["ports"] = ", ".join(v["ports"])
            writer.writerow(row)
    logger.info("Wrote %d rows to %s", len(vlans), path)


def main():
    parser = argparse.ArgumentParser(
        description="Collect VLAN inventory from a Cisco IOS switch via SSH."
    )
    parser.add_argument("-H", "--host", required=True, help="Switch IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout in seconds")
    parser.add_argument("--csv", metavar="FILE", help="Save results to CSV file")
    parser.add_argument(
        "--show-inactive",
        action="store_true",
        help="Include VLANs not in active state",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    logger.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = ssh_connect(args.host, args.username, password, args.port, args.timeout)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell(width=200, height=200)
        time.sleep(1)
        shell.recv(65535)  # discard banner / MOTD
        send_command(shell, "terminal length 0", wait=1)
        logger.info("Fetching VLAN table")
        raw = send_command(shell, "show vlan brief", wait=2.5)
    finally:
        client.close()

    vlans = parse_vlan_brief(raw)
    if not vlans:
        logger.error("No VLAN data parsed — confirm target is a Cisco IOS switch")
        sys.exit(1)

    if not args.show_inactive:
        vlans = [v for v in vlans if v["status"] == "active"]

    logger.info("Found %d VLANs on %s", len(vlans), args.host)
    display_table(vlans)

    if args.csv:
        write_csv(vlans, args.csv)


if __name__ == "__main__":
    main()