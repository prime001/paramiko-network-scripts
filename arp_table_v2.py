The write was denied. Since the request asks for script content only, here it is:

```
"""
ARP Table Analyzer with MAC Vendor Lookup

Retrieves the ARP table from a Cisco IOS/IOS-XE device via SSH, resolves each
MAC address to its hardware vendor using the IEEE OUI registry, and flags
suspicious entries such as duplicate MACs (possible ARP spoofing or HSRP
misconfiguration) and duplicate IPs (IP conflict).

Usage:
    python arp_table_analyzer.py -d 192.168.1.1 -u admin -p secret
    python arp_table_analyzer.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python arp_table_analyzer.py -d 192.168.1.1 -u admin -p secret \
        --vrf MGMT --no-vendor --output arp_report.csv

Prerequisites:
    pip install paramiko requests
    SSH must be enabled on the target device.
    Internet access is required for live OUI lookups; use --no-vendor for
    air-gapped environments.
"""

import argparse
import csv
import getpass
import logging
import re
import sys
import time
from collections import defaultdict
from datetime import datetime

import paramiko
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_ARP_RE = re.compile(
    r"^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+|-)\s+([0-9a-f.]+)\s+\w+\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_OUI_API = "https://api.macvendors.com/{}"
_oui_cache: dict[str, str] = {}


def _connect(host: str, port: int, username: str, password: str | None, key_file: str | None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(hostname=host, port=port, username=username, timeout=15)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def _run(client: paramiko.SSHClient, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=30)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return out


def _parse(raw: str) -> list[dict]:
    entries = []
    for m in _ARP_RE.finditer(raw):
        ip, age, mac, iface = m.groups()
        entries.append({
            "ip": ip,
            "age": age if age != "-" else "static",
            "mac": mac,
            "interface": iface,
            "vendor": "",
            "flags": [],
        })
    return entries


def _normalize_mac(mac: str) -> str:
    """Cisco aabb.ccdd.eeff -> AA:BB:CC:DD:EE:FF."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        return mac.upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()


def _vendor(mac: str) -> str:
    oui = _normalize_mac(mac)[:8]
    if oui in _oui_cache:
        return _oui_cache[oui]
    try:
        resp = requests.get(_OUI_API.format(oui.replace(":", "")), timeout=6)
        vendor = resp.text.strip() if resp.status_code == 200 else "Unknown"
        time.sleep(1.1)  # macvendors.com free tier: 1 req/s
    except requests.RequestException as exc:
        log.debug("OUI lookup error for %s: %s", mac, exc)
        vendor = "Lookup error"
    _oui_cache[oui] = vendor
    return vendor


def _flag_anomalies(entries: list[dict]) -> None:
    mac_ips: dict[str, list] = defaultdict(list)
    ip_macs: dict[str, list] = defaultdict(list)
    for e in entries:
        mac_ips[e["mac"]].append(e["ip"])
        ip_macs[e["ip"]].append(e["mac"])
    for e in entries:
        if len(mac_ips[e["mac"]]) > 1:
            e["flags"].append("DUP-MAC")
        if len(ip_macs[e["ip"]]) > 1:
            e["flags"].append("DUP-IP")


def _print_table(entries: list[dict], device: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nARP Analysis — {device}  [{ts}]\n")
    hdr = f"{'IP':<18} {'Age':>6}  {'MAC':<20} {'Vendor':<28} {'Interface':<20} Flags"
    print(hdr)
    print("-" * len(hdr))
    for e in entries:
        vendor = (e["vendor"][:26] + "..") if len(e["vendor"]) > 28 else e["vendor"]
        flags = ",".join(e["flags"])
        print(f"{e['ip']:<18} {e['age']:>6}  {e['mac']:<20} {vendor:<28} {e['interface']:<20} {flags}")
    dup_mac = sum(1 for e in entries if "DUP-MAC" in e["flags"])
    dup_ip = sum(1 for e in entries if "DUP-IP" in e["flags"])
    print(f"\nTotal: {len(entries)} entries | DUP-MAC: {dup_mac} | DUP-IP: {dup_ip}")
    if dup_mac:
        log.warning("DUP-MAC entries detected — investigate for ARP spoofing or HSRP peers")


def _write_csv(entries: list[dict], path: str) -> None:
    fields = ["ip", "age", "mac", "interface", "vendor", "flags"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in entries:
            row = dict(e)
            row["flags"] = "|".join(e["flags"])
            w.writerow(row)
    log.info("Report saved: %s (%d entries)", path, len(entries))


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Retrieve ARP table, resolve MAC vendors, and flag anomalies."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--key", metavar="FILE", help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--vrf", metavar="NAME", help="Retrieve ARP for a specific VRF")
    p.add_argument("--no-vendor", action="store_true", help="Skip OUI/vendor lookup")
    p.add_argument("--output", metavar="FILE", help="Write CSV report to FILE")
    p.add_argument("--debug", action="store_true", help="Enable debug output")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if not args.password and not args.key:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    cmd = f"show ip arp vrf {args.vrf}" if args.vrf else "show ip arp"

    try:
        log.info("Connecting to %s:%d", args.device, args.port)
        client = _connect(args.device, args.port, args.username, args.password, args.key)
        log.info("Running: %s", cmd)
        raw = _run(client, cmd)
        client.close()
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    entries = _parse(raw)
    if not entries:
        log.warning("No ARP entries parsed — verify device type and command output")
        log.debug("Raw output:\n%s", raw)
        sys.exit(0)

    log.info("Parsed %d ARP entries", len(entries))
    _flag_anomalies(entries)

    if not args.no_vendor:
        unique = len({e["mac"] for e in entries})
        log.info("OUI lookup for %d unique MACs (rate-limited ~1/s)", unique)
        for e in entries:
            e["vendor"] = _vendor(e["mac"])

    _print_table(entries, args.device)

    if args.output:
        _write_csv(entries, args.output)
```