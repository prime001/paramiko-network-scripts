```python
"""
arp_table_v3.py - Multi-device ARP table aggregator with conflict detection.

Connects to one or more network devices via SSH, collects ARP tables, merges
the results, and flags anomalies: duplicate MACs mapping to different IPs
(potential ARP spoofing or HSRP/VRRP) and duplicate IPs with different MACs
(IP conflict or misconfiguration).

Usage:
    python arp_table_v3.py -d 192.168.1.1 192.168.1.2 -u admin -p secret
    python arp_table_v3.py --hosts-file devices.txt -u admin --csv arp_out.csv
    python arp_table_v3.py -d 10.0.0.1 -u admin -p secret --conflicts-only

Prerequisites:
    pip install paramiko
    Devices must support "show arp" (Cisco IOS/NX-OS syntax).
"""

import argparse
import csv
import getpass
import logging
import re
import socket
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ARP_RE = re.compile(
    r"(?:Internet|Arpa)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+|-)\s+"
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\S+)"
)


def ssh_run(host: str, username: str, password: str, command: str, timeout: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.debug("%s stderr: %s", host, err)
        return output
    except (paramiko.AuthenticationException, paramiko.SSHException) as exc:
        log.error("%s SSH error: %s", host, exc)
        return ""
    except socket.timeout:
        log.error("%s connection timed out", host)
        return ""
    finally:
        client.close()


def parse_arp(output: str, source_host: str) -> List[Dict]:
    entries = []
    for line in output.splitlines():
        m = ARP_RE.search(line)
        if m:
            ip, age, mac, iface = m.groups()
            entries.append({
                "ip": ip,
                "age": age,
                "mac": mac.lower(),
                "interface": iface,
                "source": source_host,
            })
    return entries


def detect_conflicts(
    entries: List[Dict],
) -> Tuple[Dict[str, List], Dict[str, List]]:
    mac_to_ips: Dict[str, List] = defaultdict(list)
    ip_to_macs: Dict[str, List] = defaultdict(list)

    for e in entries:
        mac_to_ips[e["mac"]].append(e["ip"])
        ip_to_macs[e["ip"]].append(e["mac"])

    dup_macs = {m: list(set(ips)) for m, ips in mac_to_ips.items() if len(set(ips)) > 1}
    dup_ips = {ip: list(set(macs)) for ip, macs in ip_to_macs.items() if len(set(macs)) > 1}
    return dup_macs, dup_ips


def print_table(entries: List[Dict], conflicts_only: bool, dup_macs: Dict, dup_ips: Dict):
    header = f"{'IP':<18} {'MAC':<18} {'Age':>5}  {'Interface':<20} {'Source':<16} {'Flag'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        flags = []
        if e["mac"] in dup_macs:
            flags.append("DUP-MAC")
        if e["ip"] in dup_ips:
            flags.append("DUP-IP")
        flag_str = ",".join(flags)
        if conflicts_only and not flag_str:
            continue
        print(
            f"{e['ip']:<18} {e['mac']:<18} {e['age']:>5}  "
            f"{e['interface']:<20} {e['source']:<16} {flag_str}"
        )


def write_csv(path: str, entries: List[Dict], dup_macs: Dict, dup_ips: Dict):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "mac", "age", "interface", "source", "flags"])
        writer.writeheader()
        for e in entries:
            flags = []
            if e["mac"] in dup_macs:
                flags.append("DUP-MAC")
            if e["ip"] in dup_ips:
                flags.append("DUP-IP")
            writer.writerow({**e, "flags": ",".join(flags)})
    log.info("CSV written to %s", path)


def load_hosts_file(path: str) -> List[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Multi-device ARP aggregator with conflict detection")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--devices", nargs="+", metavar="HOST", help="Device IPs or hostnames")
    group.add_argument("--hosts-file", metavar="FILE", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout in seconds")
    parser.add_argument("--csv", metavar="FILE", help="Write results to CSV file")
    parser.add_argument("--conflicts-only", action="store_true", help="Print only conflicting entries")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")
    hosts = args.devices if args.devices else load_hosts_file(args.hosts_file)

    all_entries: List[Dict] = []
    for host in hosts:
        log.info("Connecting to %s", host)
        output = ssh_run(host, args.username, password, "show arp", args.timeout)
        if not output:
            log.warning("No output from %s — skipping", host)
            continue
        entries = parse_arp(output, host)
        log.info("%s: %d ARP entries", host, len(entries))
        all_entries.extend(entries)

    if not all_entries:
        log.error("No ARP data collected from any device")
        sys.exit(1)

    dup_macs, dup_ips = detect_conflicts(all_entries)

    if dup_macs:
        log.warning("Duplicate MACs (same MAC, multiple IPs): %d", len(dup_macs))
        for mac, ips in dup_macs.items():
            log.warning("  %s -> %s", mac, ", ".join(ips))

    if dup_ips:
        log.warning("Duplicate IPs (same IP, multiple MACs): %d", len(dup_ips))
        for ip, macs in dup_ips.items():
            log.warning("  %s -> %s", ip, ", ".join(macs))

    print_table(all_entries, args.conflicts_only, dup_macs, dup_ips)
    print(f"\nTotal entries: {len(all_entries)} | Duplicate MACs: {len(dup_macs)} | Duplicate IPs: {len(dup_ips)}")

    if args.csv:
        write_csv(args.csv, all_entries, dup_macs, dup_ips)


if __name__ == "__main__":
    main()
```