```python
"""
arp_table_analysis.py - ARP Table Analysis and Anomaly Detection

Purpose:
    Retrieves ARP tables from network devices via SSH and performs analysis
    to detect duplicate IP addresses, duplicate MAC addresses (potential MAC
    spoofing), and stale or incomplete entries. Results can be exported to CSV.

Usage:
    python arp_table_analysis.py -d 192.168.1.1 -u admin -p secret
    python arp_table_analysis.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python arp_table_analysis.py -d 192.168.1.1 -u admin -p secret --subnet 10.0.0.0/24
    python arp_table_analysis.py -d 192.168.1.1 -u admin -p secret --csv arp_out.csv
    python arp_table_analysis.py -d 192.168.1.1 -u admin -p secret --anomalies-only

Prerequisites:
    pip install paramiko
    Device must support: show ip arp (Cisco IOS/NX-OS)
"""

import argparse
import csv
import ipaddress
import logging
import re
import sys
from collections import defaultdict
from getpass import getpass

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

ARP_PATTERN = re.compile(
    r"(?P<protocol>\S+)\s+"
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"(?P<age>[-\d]+)\s+"
    r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|Incomplete)\s+"
    r"(?P<encap>\S+)\s+"
    r"(?P<interface>\S+)",
    re.IGNORECASE,
)


def ssh_connect(host, username, password=None, key_path=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("Provide either password or key_path")
    client.connect(**connect_kwargs)
    return client


def run_command(client, command, timeout=30):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    if error.strip():
        log.debug("stderr: %s", error.strip())
    return output


def parse_arp_table(raw_output):
    entries = []
    for line in raw_output.splitlines():
        match = ARP_PATTERN.search(line)
        if match:
            entries.append(match.groupdict())
    return entries


def filter_by_subnet(entries, subnet_str):
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError as exc:
        log.error("Invalid subnet %s: %s", subnet_str, exc)
        return entries
    return [e for e in entries if ipaddress.ip_address(e["ip"]) in network]


def detect_anomalies(entries):
    ip_to_macs = defaultdict(list)
    mac_to_ips = defaultdict(list)
    incomplete = []

    for entry in entries:
        ip = entry["ip"]
        mac = entry["mac"]
        if mac.lower() == "incomplete":
            incomplete.append(entry)
            continue
        ip_to_macs[ip].append(mac)
        mac_to_ips[mac].append(ip)

    duplicate_ips = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
    duplicate_macs = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}

    return {
        "duplicate_ips": duplicate_ips,
        "duplicate_macs": duplicate_macs,
        "incomplete": incomplete,
    }


def print_table(entries):
    if not entries:
        print("No ARP entries found.")
        return
    header = f"{'IP':<18} {'MAC':<18} {'Interface':<20} {'Age':>6} {'Protocol':<10}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(
            f"{e['ip']:<18} {e['mac']:<18} {e['interface']:<20} "
            f"{e['age']:>6} {e['protocol']:<10}"
        )


def print_anomalies(anomalies):
    dup_ips = anomalies["duplicate_ips"]
    dup_macs = anomalies["duplicate_macs"]
    incomplete = anomalies["incomplete"]

    if dup_ips:
        print("\n[!] Duplicate IPs (possible IP conflict):")
        for ip, macs in dup_ips.items():
            print(f"    {ip} -> {', '.join(macs)}")
    if dup_macs:
        print("\n[!] Duplicate MACs (possible MAC spoofing or HSRP/VRRP):")
        for mac, ips in dup_macs.items():
            print(f"    {mac} -> {', '.join(ips)}")
    if incomplete:
        print(f"\n[!] Incomplete entries: {len(incomplete)}")
        for e in incomplete:
            print(f"    {e['ip']} on {e['interface']}")
    if not dup_ips and not dup_macs and not incomplete:
        print("\n[+] No anomalies detected.")


def export_csv(entries, path):
    if not entries:
        log.warning("No entries to export.")
        return
    fields = ["ip", "mac", "interface", "age", "protocol", "encap"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(entries)
    log.info("Exported %d entries to %s", len(entries), path)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze ARP table from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_path", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--subnet", default=None, help="Filter results to subnet (e.g. 10.0.0.0/24)")
    parser.add_argument("--csv", dest="csv_path", default=None, help="Export results to CSV file")
    parser.add_argument("--anomalies-only", action="store_true", help="Only print anomaly report")
    parser.add_argument("--vrf", default=None, help="VRF name for ARP lookup")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_path:
        args.password = getpass(f"Password for {args.username}@{args.device}: ")

    command = "show ip arp"
    if args.vrf:
        command = f"show ip arp vrf {args.vrf}"

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(
            host=args.device,
            username=args.username,
            password=args.password,
            key_path=args.key_path,
            port=args.port,
        )
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Running: %s", command)
        raw = run_command(client, command)
    except Exception as exc:
        log.error("Command execution failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    entries = parse_arp_table(raw)
    if not entries:
        log.warning("No ARP entries parsed. Check device output format.")
        sys.exit(0)

    log.info("Parsed %d ARP entries", len(entries))

    if args.subnet:
        entries = filter_by_subnet(entries, args.subnet)
        log.info("%d entries after subnet filter (%s)", len(entries), args.subnet)

    anomalies = detect_anomalies(entries)

    if not args.anomalies_only:
        print_table(entries)

    print_anomalies(anomalies)

    if args.csv_path:
        export_csv(entries, args.csv_path)
```