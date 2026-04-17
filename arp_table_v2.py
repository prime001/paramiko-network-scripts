```python
"""
arp_table_collector.py - ARP Table Collector with MAC Vendor Lookup

Purpose:
    Retrieve the ARP table from a Cisco IOS/IOS-XE device via SSH, enrich
    each entry with the IEEE OUI vendor name, flag duplicate IP/MAC anomalies,
    and optionally export results to CSV.

Usage:
    python arp_table_collector.py -d 192.168.1.1 -u admin -p secret
    python arp_table_collector.py -d 192.168.1.1 -u admin --vlan 10 --csv arp_out.csv
    python arp_table_collector.py -d 192.168.1.1 -u admin --subnet 10.0.0.0/24 --anomalies

Prerequisites:
    pip install paramiko requests
"""

import argparse
import csv
import ipaddress
import logging
import re
import sys
import time
from collections import defaultdict

import paramiko
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

OUI_API = "https://api.macvendors.com/{}"
OUI_CACHE: dict[str, str] = {}


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password, timeout=15)
    log.info("Connected to %s", host)
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def parse_arp_table(raw: str) -> list[dict]:
    """Parse 'show ip arp' output into structured records."""
    pattern = re.compile(
        r"^(?P<protocol>\S+)\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<age>\S+)\s+"
        r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(?P<encap>\S+)\s+(?P<iface>\S+)",
        re.IGNORECASE | re.MULTILINE,
    )
    entries = []
    for m in pattern.finditer(raw):
        entries.append({
            "protocol": m.group("protocol"),
            "ip": m.group("ip"),
            "age": m.group("age"),
            "mac": m.group("mac").lower(),
            "encap": m.group("encap"),
            "interface": m.group("iface"),
        })
    return entries


def cisco_mac_to_ieee(cisco_mac: str) -> str:
    """Convert Cisco dotted-hex (aabb.ccdd.eeff) to IEEE colon format."""
    flat = cisco_mac.replace(".", "")
    return ":".join(flat[i:i+2] for i in range(0, 12, 2))


def lookup_vendor(cisco_mac: str) -> str:
    ieee = cisco_mac_to_ieee(cisco_mac)
    oui = ieee[:8].upper()
    if oui in OUI_CACHE:
        return OUI_CACHE[oui]
    try:
        resp = requests.get(OUI_API.format(ieee), timeout=5)
        if resp.status_code == 200:
            vendor = resp.text.strip()
        elif resp.status_code == 404:
            vendor = "Unknown"
        else:
            vendor = "Lookup failed"
        time.sleep(0.4)  # respect rate limit
    except requests.RequestException as exc:
        log.debug("OUI lookup failed for %s: %s", ieee, exc)
        vendor = "Lookup error"
    OUI_CACHE[oui] = vendor
    return vendor


def detect_anomalies(entries: list[dict]) -> list[str]:
    """Return a list of anomaly descriptions."""
    anomalies = []
    ip_to_macs: dict[str, list[str]] = defaultdict(list)
    mac_to_ips: dict[str, list[str]] = defaultdict(list)
    for e in entries:
        ip_to_macs[e["ip"]].append(e["mac"])
        mac_to_ips[e["mac"]].append(e["ip"])
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            anomalies.append(f"Duplicate IP {ip} maps to MACs: {', '.join(macs)}")
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            anomalies.append(f"Duplicate MAC {mac} maps to IPs: {', '.join(ips)}")
    return anomalies


def filter_entries(
    entries: list[dict],
    vlan: str | None,
    subnet: str | None,
) -> list[dict]:
    result = entries
    if vlan:
        result = [e for e in result if e["interface"].endswith(vlan)]
    if subnet:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            result = [e for e in result if ipaddress.ip_address(e["ip"]) in network]
        except ValueError as exc:
            log.error("Invalid subnet %s: %s", subnet, exc)
    return result


def print_table(entries: list[dict]) -> None:
    header = f"{'IP':<18} {'MAC':<20} {'Age':<6} {'Interface':<22} {'Vendor'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(
            f"{e['ip']:<18} {e['mac']:<20} {e['age']:<6} "
            f"{e['interface']:<22} {e.get('vendor', '')}"
        )


def write_csv(entries: list[dict], path: str) -> None:
    fields = ["ip", "mac", "age", "encap", "interface", "vendor"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(entries)
    log.info("Saved %d entries to %s", len(entries), path)


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrieve ARP table with MAC vendor enrichment"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument("--vlan", help="Filter by VLAN ID (matches interface suffix)")
    parser.add_argument("--subnet", help="Filter by subnet in CIDR notation")
    parser.add_argument("--no-vendor", action="store_true", help="Skip MAC vendor lookup")
    parser.add_argument("--anomalies", action="store_true", help="Report ARP anomalies")
    parser.add_argument("--csv", metavar="FILE", help="Export results to CSV file")
    return parser.parse_args()


if __name__ == "__main__":
    args = build_args()

    if args.password is None:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = ssh_connect(args.device, args.username, args.password, args.port)
        raw = run_command(client, "show ip arp")
        client.close()
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    entries = parse_arp_table(raw)
    if not entries:
        log.warning("No ARP entries parsed — check device output format")
        sys.exit(0)

    entries = filter_entries(entries, args.vlan, args.subnet)
    log.info("Entries after filtering: %d", len(entries))

    if not args.no_vendor:
        log.info("Resolving MAC vendors (may take a moment)...")
        for e in entries:
            e["vendor"] = lookup_vendor(e["mac"])
    else:
        for e in entries:
            e["vendor"] = ""

    print_table(entries)

    if args.anomalies:
        problems = detect_anomalies(entries)
        if problems:
            print("\n[ANOMALIES]")
            for p in problems:
                print(f"  ! {p}")
        else:
            print("\n[ANOMALIES] None detected")

    if args.csv:
        write_csv(entries, args.csv)
```