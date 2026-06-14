ARP Cross-Device Correlation and Anomaly Detector

Collects ARP tables from multiple network devices and correlates entries
across the fleet to surface duplicate IPs (potential conflicts or ARP spoofing),
MAC addresses roaming across subnets, and per-vendor fleet breakdowns.

Usage:
    python arp_table_v3.py -d 10.0.0.1 10.0.0.2 -u admin -p secret
    python arp_table_v3.py -d 10.0.0.1 -u admin --key ~/.ssh/id_rsa --oui
    python arp_table_v3.py -d 10.0.0.1 10.0.0.2 -u admin -p secret --anomalies-only

Prerequisites:
    pip install paramiko
    Devices must support 'show arp' (Cisco IOS/IOS-XE/NX-OS).
"""

import argparse
import getpass
import ipaddress
import logging
import re
import sys
from collections import defaultdict
from typing import Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ARP_RE = re.compile(
    r"(?:Internet|ARPA)\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"\d+\s+"
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F:]{17}|-)\s+"
    r"\S+\s+"
    r"(\S+)"
)

OUI_CACHE: dict = {}


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        return mac.lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)).lower()


def oui_vendor(mac: str) -> str:
    oui = normalize_mac(mac).replace(":", "")[:6].upper()
    if oui in OUI_CACHE:
        return OUI_CACHE[oui]
    try:
        import urllib.request

        url = f"https://api.macvendors.com/{oui}"
        with urllib.request.urlopen(url, timeout=3) as resp:
            vendor = resp.read().decode().strip()
    except Exception:
        vendor = "Unknown"
    OUI_CACHE[oui] = vendor
    return vendor


def run_command(client: paramiko.SSHClient, cmd: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr from device: %s", err)
    return out


def connect(
    host: str,
    username: str,
    password: Optional[str],
    key_path: Optional[str],
    port: int,
    timeout: int,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=key_path is None,
        allow_agent=True,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
    elif password:
        connect_kwargs["password"] = password
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    client.connect(**connect_kwargs)
    return client


def fetch_arp(
    host: str,
    username: str,
    password: Optional[str],
    key_path: Optional[str],
    port: int,
    timeout: int,
) -> list:
    entries = []
    try:
        client = connect(host, username, password, key_path, port, timeout)
    except Exception as exc:
        log.error("Cannot connect to %s: %s", host, exc)
        return entries

    try:
        output = run_command(client, "show arp")
        for line in output.splitlines():
            m = ARP_RE.search(line)
            if not m:
                continue
            ip, mac, iface = m.group(1), m.group(2), m.group(3)
            if mac == "-":
                continue
            entries.append(
                {
                    "device": host,
                    "ip": ip,
                    "mac": normalize_mac(mac),
                    "interface": iface,
                }
            )
    except Exception as exc:
        log.error("Error collecting ARP from %s: %s", host, exc)
    finally:
        client.close()

    log.info("Collected %d ARP entries from %s", len(entries), host)
    return entries


def detect_anomalies(all_entries: list) -> tuple:
    ip_to_macs = defaultdict(list)
    mac_to_ips = defaultdict(list)

    for e in all_entries:
        ip_to_macs[e["ip"]].append(e)
        mac_to_ips[e["mac"]].append(e)

    dup_ips = {
        ip: entries
        for ip, entries in ip_to_macs.items()
        if len(set(x["mac"] for x in entries)) > 1
    }
    roaming_macs = {
        mac: entries
        for mac, entries in mac_to_ips.items()
        if len(set(x["ip"] for x in entries)) > 1
    }
    return dup_ips, roaming_macs


def print_table(entries: list, oui: bool) -> None:
    col = "{:<18} {:<20} {:<20} {:<16} {}"
    header = col.format("Device", "IP Address", "MAC Address", "Interface", "Vendor" if oui else "")
    print(header)
    print("-" * max(len(header), 60))
    for e in sorted(entries, key=lambda x: (x["device"], ipaddress.ip_address(x["ip"]))):
        vendor = oui_vendor(e["mac"]) if oui else ""
        print(col.format(e["device"], e["ip"], e["mac"], e["interface"], vendor))


def print_anomalies(dup_ips: dict, roaming_macs: dict) -> None:
    if dup_ips:
        print("\n[!] Duplicate IP addresses (same IP -> multiple MACs):")
        for ip, entries in sorted(dup_ips.items()):
            macs = ", ".join(set(e["mac"] for e in entries))
            devices = ", ".join(set(e["device"] for e in entries))
            print(f"    {ip}  MACs={macs}  seen_on={devices}")
    else:
        print("\n[+] No duplicate IP addresses detected.")

    if roaming_macs:
        print("\n[!] Roaming MACs (same MAC -> multiple IPs):")
        for mac, entries in sorted(roaming_macs.items()):
            ips = ", ".join(sorted(set(e["ip"] for e in entries)))
            devices = ", ".join(set(e["device"] for e in entries))
            print(f"    {mac}  IPs={ips}  seen_on={devices}")
    else:
        print("\n[+] No roaming MACs detected.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect and cross-correlate ARP tables across multiple devices."
    )
    parser.add_argument("-d", "--devices", nargs="+", required=True, metavar="HOST")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", dest="key_path", default=None, metavar="PATH")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--oui", action="store_true", help="Resolve MAC OUI vendor names via API")
    parser.add_argument(
        "--anomalies-only",
        action="store_true",
        help="Print only anomaly report, skip full table",
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_path:
        password = getpass.getpass(f"Password for {args.username}: ")

    all_entries = []
    for host in args.devices:
        entries = fetch_arp(
            host, args.username, password, args.key_path, args.port, args.timeout
        )
        all_entries.extend(entries)

    if not all_entries:
        log.error("No ARP entries collected from any device.")
        sys.exit(1)

    if not args.anomalies_only:
        print(
            f"\nConsolidated ARP Table "
            f"({len(all_entries)} entries across {len(args.devices)} device(s)):\n"
        )
        print_table(all_entries, args.oui)

    dup_ips, roaming_macs = detect_anomalies(all_entries)
    print_anomalies(dup_ips, roaming_macs)

    if dup_ips or roaming_macs:
        sys.exit(2)


if __name__ == "__main__":
    main()