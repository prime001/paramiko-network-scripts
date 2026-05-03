arp_table_enriched.py - ARP Table with MAC Vendor Lookup and Duplicate IP Detection

Purpose:
    Retrieves and enriches ARP table data from Cisco IOS/IOS-XE devices via SSH.
    Performs OUI-based vendor lookup and flags duplicate IP entries that may
    indicate ARP spoofing or misconfigured hosts sharing an address.

Usage:
    python arp_table_enriched.py -d 192.168.1.1 -u admin -p secret
    python arp_table_enriched.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python arp_table_enriched.py -d 192.168.1.1 -u admin -p secret --filter 10.0.1.0/24
    python arp_table_enriched.py -d 192.168.1.1 -u admin -p secret --format csv -o out.csv
    python arp_table_enriched.py -d 192.168.1.1 -u admin -p secret --no-vendor --format json -o out.json

Prerequisites:
    pip install paramiko
    pip install requests  (optional, enables MAC vendor lookup)
    SSH access to target device with privilege to run 'show arp'
"""

import argparse
import csv
import ipaddress
import json
import logging
import re
import sys
import time
from collections import defaultdict

import paramiko

try:
    import requests
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_ARP_RE = re.compile(
    r"(?P<protocol>\S+)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<age>\d+|-)\s+"
    r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
    r"(?P<encap>\S+)\s+"
    r"(?P<interface>\S+)",
    re.IGNORECASE,
)


def _cisco_to_colon_mac(cisco: str) -> str:
    raw = cisco.replace(".", "")
    return ":".join(raw[i:i + 2].upper() for i in range(0, 12, 2))


def _oui(mac_colon: str) -> str:
    return mac_colon.replace(":", "")[:6].upper()


def vendor_lookup(mac_colon: str, cache: dict) -> str:
    oui = _oui(mac_colon)
    if oui in cache:
        return cache[oui]
    try:
        resp = requests.get(f"https://api.macvendors.com/{oui}", timeout=3)
        vendor = resp.text.strip() if resp.status_code == 200 else "Unknown"
    except requests.RequestException:
        vendor = "Unknown"
    cache[oui] = vendor
    time.sleep(0.12)
    return vendor


def fetch_arp(host: str, username: str, password: str = None,
              key_file: str = None, port: int = 22, timeout: int = 15) -> str:
    if not password and not key_file:
        raise ValueError("Provide --password or --key for authentication.")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = {"hostname": host, "port": port, "username": username,
          "timeout": timeout, "look_for_keys": bool(key_file), "allow_agent": False}
    if key_file:
        kw["key_filename"] = key_file
    else:
        kw["password"] = password
    log.info("Connecting to %s:%d", host, port)
    try:
        client.connect(**kw)
        _, stdout, stderr = client.exec_command("show arp", timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.warning("Device stderr: %s", err)
        return out
    finally:
        client.close()


def parse_arp(raw: str) -> list:
    entries = []
    for line in raw.splitlines():
        m = _ARP_RE.search(line)
        if not m:
            continue
        entries.append({
            "ip": m.group("ip"),
            "age": m.group("age"),
            "mac": _cisco_to_colon_mac(m.group("mac")),
            "encap": m.group("encap"),
            "interface": m.group("interface"),
            "protocol": m.group("protocol"),
            "vendor": "",
            "duplicate_ip": False,
        })
    return entries


def flag_duplicates(entries: list) -> None:
    ip_macs = defaultdict(set)
    for e in entries:
        ip_macs[e["ip"]].add(e["mac"])
    for e in entries:
        if len(ip_macs[e["ip"]]) > 1:
            e["duplicate_ip"] = True


def enrich(entries: list) -> None:
    cache: dict = {}
    for e in entries:
        e["vendor"] = vendor_lookup(e["mac"], cache)


def subnet_filter(entries: list, cidr: str) -> list:
    net = ipaddress.ip_network(cidr, strict=False)
    return [e for e in entries if ipaddress.ip_address(e["ip"]) in net]


def render_table(entries: list) -> None:
    if not entries:
        print("No ARP entries.")
        return
    W = (16, 19, 5, 22, 26, 5)
    hdr = (f"{'IP ADDRESS':<{W[0]}} {'MAC ADDRESS':<{W[1]}} {'AGE':>{W[2]}} "
           f"{'INTERFACE':<{W[3]}} {'VENDOR':<{W[4]}} {'DUP?':<{W[5]}}")
    print(hdr)
    print("-" * len(hdr))
    for e in entries:
        flag = "YES" if e["duplicate_ip"] else ""
        print(f"{e['ip']:<{W[0]}} {e['mac']:<{W[1]}} {e['age']:>{W[2]}} "
              f"{e['interface']:<{W[3]}} {e['vendor']:<{W[4]}} {flag:<{W[5]}}")
    dups = sum(1 for e in entries if e["duplicate_ip"])
    print(f"\n{len(entries)} entries — {dups} duplicate IP(s) flagged")


def write_csv(entries: list, path: str) -> None:
    fields = ["ip", "mac", "age", "interface", "protocol", "encap", "vendor", "duplicate_ip"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(entries)
    print(f"CSV written: {path}")


def write_json(entries: list, path: str) -> None:
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)
    print(f"JSON written: {path}")


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Fetch and enrich ARP tables from Cisco IOS/IOS-XE devices via SSH."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--key", metavar="FILE", help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    p.add_argument("--timeout", type=int, default=15, help="Seconds before timeout")
    p.add_argument("--filter", metavar="CIDR", dest="subnet",
                   help="Restrict output to a subnet, e.g. 192.168.1.0/24")
    p.add_argument("--no-vendor", action="store_true",
                   help="Skip OUI vendor lookup (faster, no outbound HTTP)")
    p.add_argument("--format", choices=["table", "csv", "json"], default="table",
                   help="Output format (default: table)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Output file path (required for csv/json formats)")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p


def main() -> int:
    parser = build_args()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.format in ("csv", "json") and not args.output:
        parser.error(f"--output is required when --format={args.format}")
    if not args.password and not args.key:
        parser.error("Provide --password or --key.")

    try:
        raw = fetch_arp(args.device, args.username, password=args.password,
                        key_file=args.key, port=args.port, timeout=args.timeout)
    except paramiko.AuthenticationException as exc:
        log.error("Authentication failed: %s", exc)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    entries = parse_arp(raw)
    if not entries:
        print("No ARP entries parsed. Verify device output format.", file=sys.stderr)
        return 1

    if args.subnet:
        entries = subnet_filter(entries, args.subnet)

    flag_duplicates(entries)

    if not args.no_vendor:
        if _REQUESTS:
            enrich(entries)
        else:
            log.warning("'requests' not installed; skipping vendor lookup (pip install requests)")

    if args.format == "table":
        render_table(entries)
    elif args.format == "csv":
        write_csv(entries, args.output)
    elif args.format == "json":
        write_json(entries, args.output)

    return 0 if not any(e["duplicate_ip"] for e in entries) else 2


if __name__ == "__main__":
    sys.exit(main())