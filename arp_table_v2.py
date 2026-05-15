```python
"""
arp_table_v3.py - ARP table collector with MAC vendor (OUI) resolution.

Retrieves the ARP table from a Cisco IOS/IOS-XE device via SSH and
resolves each MAC address to its IEEE OUI vendor string using the
macvendors.com public API.  Results can be filtered by IP subnet prefix
or MAC prefix and exported to CSV.

Usage:
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret
    python arp_table_v3.py -d 192.168.1.1 -u admin --filter-ip 10.0.1 --csv out.csv
    python arp_table_v3.py -d 192.168.1.1 -u admin --filter-mac 00:1A --no-vendor

Prerequisites:
    pip install paramiko
    Internet access for vendor lookup (or use --no-vendor to skip)
"""

import argparse
import csv
import getpass
import logging
import re
import sys
import time
import urllib.error
import urllib.request

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ARP_RE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)"
)


def normalize_mac(cisco_mac: str) -> str:
    """Convert Cisco dotted-quartet MAC to colon-separated uppercase."""
    hex_only = cisco_mac.replace(".", "")
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2)).upper()


def lookup_vendor(mac_colon: str, timeout: int = 4) -> str:
    oui = mac_colon.replace(":", "")[:6]
    url = f"https://api.macvendors.com/{oui}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode().strip()
    except urllib.error.HTTPError:
        return "Unknown"
    except Exception:
        return "Lookup failed"


def get_arp_table(host: str, username: str, password: str, port: int = 22) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        log.info("Connecting to %s:%d", host, port)
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
        )
        chan = client.invoke_shell()
        time.sleep(0.5)
        chan.send("terminal length 0\n")
        time.sleep(0.3)
        chan.recv(4096)
        chan.send("show arp\n")
        time.sleep(1.2)
        output = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            if chan.recv_ready():
                output += chan.recv(65535)
            else:
                time.sleep(0.1)
        return output.decode(errors="replace")
    finally:
        client.close()


def parse_arp(raw: str) -> list[dict]:
    entries = []
    for line in raw.splitlines():
        m = ARP_RE.search(line.lower())
        if not m:
            continue
        ip, mac_dot, iface = m.groups()
        entries.append({
            "ip": ip,
            "mac_cisco": mac_dot.upper(),
            "mac": normalize_mac(mac_dot),
            "interface": iface,
            "vendor": "",
        })
    return entries


def apply_filters(
    entries: list[dict], filter_ip: str | None, filter_mac: str | None
) -> list[dict]:
    if filter_ip:
        entries = [e for e in entries if e["ip"].startswith(filter_ip)]
    if filter_mac:
        entries = [e for e in entries if e["mac"].upper().startswith(filter_mac.upper())]
    return entries


def print_table(entries: list[dict], show_vendor: bool) -> None:
    width = 62 + (32 if show_vendor else 0)
    header = f"{'IP Address':<18} {'MAC Address':<20} {'Interface':<20}"
    if show_vendor:
        header += " Vendor"
    print(header)
    print("-" * width)
    for e in entries:
        row = f"{e['ip']:<18} {e['mac']:<20} {e['interface']:<20}"
        if show_vendor:
            row += f" {e['vendor']}"
        print(row)
    print(f"\n{len(entries)} entries")


def write_csv(entries: list[dict], path: str, show_vendor: bool) -> None:
    fields = ["ip", "mac", "interface"]
    if show_vendor:
        fields.append("vendor")
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(entries)
    log.info("Wrote %d entries to %s", len(entries), path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ARP table collector with MAC OUI vendor resolution"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument(
        "--filter-ip", metavar="PREFIX",
        help="Show only entries whose IP starts with PREFIX (e.g. 10.0.1)"
    )
    parser.add_argument(
        "--filter-mac", metavar="PREFIX",
        help="Show only entries whose MAC starts with PREFIX (e.g. 00:1A)"
    )
    parser.add_argument(
        "--no-vendor", action="store_true",
        help="Skip OUI vendor lookup (faster, no internet required)"
    )
    parser.add_argument("--csv", metavar="FILE", help="Export results to a CSV file")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    show_vendor = not args.no_vendor

    try:
        raw = get_arp_table(args.device, args.username, password, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    entries = parse_arp(raw)
    entries = apply_filters(entries, args.filter_ip, args.filter_mac)

    if not entries:
        log.warning("No ARP entries matched (check filters or device output)")
        sys.exit(0)

    if show_vendor:
        log.info("Resolving vendors for %d entries (1 req/sec rate limit)...", len(entries))
        for i, entry in enumerate(entries):
            entry["vendor"] = lookup_vendor(entry["mac"])
            if i < len(entries) - 1:
                time.sleep(1.1)

    print_table(entries, show_vendor)

    if args.csv:
        write_csv(entries, args.csv, show_vendor)


if __name__ == "__main__":
    main()
```