```python
"""
neighbor_discovery.py - CDP/LLDP neighbor topology collector via SSH

Purpose:
    Connects to one or more Cisco IOS/IOS-XE devices over SSH and retrieves
    CDP (Cisco Discovery Protocol) and/or LLDP neighbor tables, producing a
    structured report of adjacent devices.  Useful for automated topology
    audits, cable-plant verification, and pre/post-change snapshots.

Usage:
    # Single device, CDP only (default)
    python neighbor_discovery.py -H 192.168.1.1 -u admin -p secret

    # Multiple devices from file, both protocols, save to CSV
    python neighbor_discovery.py -f devices.txt -u admin \
        --password-env NET_PASS --protocol both --output neighbors.csv

Prerequisites:
    pip install paramiko
    SSH access to target devices.
    CDP and/or LLDP must be globally enabled on the queried devices.
"""

import argparse
import csv
import logging
import os
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

FIELDS = ["source_device", "protocol", "device_id", "ip_address",
          "local_interface", "remote_interface", "platform"]


def ssh_run(host, username, password, command, port=22, timeout=15, wait=2.5):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
        )
        shell = client.invoke_shell()
        time.sleep(0.5)
        shell.recv(65535)
        shell.send("terminal length 0\n")
        time.sleep(0.3)
        shell.recv(65535)
        shell.send(command + "\n")
        time.sleep(wait)
        buf = b""
        while shell.recv_ready():
            buf += shell.recv(65535)
        return buf.decode("utf-8", errors="replace")
    finally:
        client.close()


def parse_cdp(raw):
    neighbors = []
    for block in re.split(r"-{10,}", raw):
        if "Device ID" not in block:
            continue
        n = {"protocol": "CDP", "platform": "", "ip_address": "",
             "local_interface": "", "remote_interface": ""}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        else:
            continue
        m = re.search(r"IP address:\s*(\S+)", block)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"Platform:\s*(.+?),", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+?),\s*Port ID[^:]*:\s*(\S+)", block)
        if m:
            n["local_interface"] = m.group(1)
            n["remote_interface"] = m.group(2)
        neighbors.append(n)
    return neighbors


def parse_lldp(raw):
    neighbors = []
    for block in re.split(r"-{10,}", raw):
        if "System Name" not in block and "Port id" not in block:
            continue
        n = {"protocol": "LLDP", "platform": "", "ip_address": "",
             "local_interface": "", "remote_interface": ""}
        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        else:
            m = re.search(r"Chassis id:\s*(\S+)", block)
            n["device_id"] = m.group(1) if m else "unknown"
        m = re.search(r"(?:Management Addresses?|IP):\s*(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"System Description.*?:\s*(.+?)(?:\n|$)", block, re.DOTALL)
        if m:
            n["platform"] = m.group(1).strip()[:64]
        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            n["local_interface"] = m.group(1)
        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            n["remote_interface"] = m.group(1)
        neighbors.append(n)
    return neighbors


def collect(host, username, password, port, protocol):
    logger.info("Connecting to %s", host)
    neighbors = []
    try:
        if protocol in ("cdp", "both"):
            raw = ssh_run(host, username, password, "show cdp neighbors detail", port=port)
            found = parse_cdp(raw)
            logger.info("%s: %d CDP neighbor(s)", host, len(found))
            neighbors.extend(found)
        if protocol in ("lldp", "both"):
            raw = ssh_run(host, username, password, "show lldp neighbors detail", port=port)
            found = parse_lldp(raw)
            logger.info("%s: %d LLDP neighbor(s)", host, len(found))
            neighbors.extend(found)
    except paramiko.AuthenticationException:
        logger.error("%s: authentication failed", host)
    except Exception as exc:
        logger.error("%s: %s", host, exc)
    for n in neighbors:
        n["source_device"] = host
    return neighbors


def print_table(rows):
    widths = {f: len(f) for f in FIELDS}
    for row in rows:
        for f in FIELDS:
            widths[f] = max(widths[f], len(row.get(f, "")))
    header = "  ".join(f.upper().ljust(widths[f]) for f in FIELDS)
    print(header)
    print("-" * len(header))
    for row in rows:
        print("  ".join(row.get(f, "").ljust(widths[f]) for f in FIELDS))


def write_csv(rows, path):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Saved %d row(s) to %s", len(rows), path)


def build_parser():
    p = argparse.ArgumentParser(
        description="Collect CDP/LLDP neighbor tables from Cisco IOS devices"
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-H", "--host", help="Single device IP or hostname")
    target.add_argument("-f", "--file", help="File with one device per line")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--password-env", default="NET_PASSWORD",
                   help="Env var for SSH password (default: NET_PASSWORD)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--protocol", choices=("cdp", "lldp", "both"), default="cdp",
                   help="Protocol to query (default: cdp)")
    p.add_argument("--output", metavar="FILE", help="Save results to CSV")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or os.environ.get(args.password_env)
    if not password:
        logger.error("No password. Use -p or export %s=<value>.", args.password_env)
        sys.exit(1)

    if args.host:
        hosts = [args.host]
    else:
        try:
            with open(args.file) as fh:
                hosts = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            logger.error("Cannot read device file: %s", exc)
            sys.exit(1)

    all_neighbors = []
    for host in hosts:
        all_neighbors.extend(collect(host, args.username, password, args.port, args.protocol))

    if not all_neighbors:
        logger.warning("No neighbors discovered.")
        sys.exit(0)

    print_table(all_neighbors)

    if args.output:
        write_csv(all_neighbors, args.output)
```