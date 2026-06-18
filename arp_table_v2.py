```python
"""
ARP Table Collector with MAC Vendor Resolution

Purpose:
    SSH into a network device, retrieve the ARP table, normalize MAC addresses,
    optionally resolve OUI prefixes to vendor names via the macvendors.com API,
    and flag duplicate IPs (potential ARP spoofing or misconfig).

Usage:
    python arp_table_v3.py -d 192.168.1.1 -u admin
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret --vendor-lookup
    python arp_table_v3.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa --output arp.json
    python arp_table_v3.py -d 192.168.1.1 -u admin --command "show ip arp vrf MGMT"

Prerequisites:
    pip install paramiko
    pip install requests   # optional, required for --vendor-lookup
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass

import paramiko

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# Matches Cisco IOS dotted-quad MAC (aabb.ccdd.eeff) and standard colon/dash forms
_ARP_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"\s+(?P<age>\d+|-+)\s+"
    r"(?P<mac>"
    r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"  # IOS dotted
    r"|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"             # colon
    r"|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}"             # dash
    r")"
    r"\s+(?P<iface>\S+)"
)


def normalize_mac(raw: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(digits) != 12:
        return raw.upper()
    return ":".join(digits[i:i + 2].upper() for i in range(0, 12, 2))


def vendor_for_mac(mac: str) -> str:
    if not HAS_REQUESTS:
        return ""
    try:
        resp = _requests.get(
            f"https://api.macvendors.com/{mac}", timeout=3
        )
        return resp.text.strip() if resp.status_code == 200 else ""
    except _requests.RequestException:
        return ""


def parse_arp(raw: str) -> list:
    entries = []
    for line in raw.splitlines():
        m = _ARP_RE.search(line)
        if m:
            entries.append({
                "ip": m.group("ip"),
                "mac": normalize_mac(m.group("mac")),
                "age": m.group("age"),
                "interface": m.group("iface"),
                "vendor": "",
            })
    return entries


def find_duplicate_ips(entries: list) -> dict:
    seen: dict = {}
    for e in entries:
        seen.setdefault(e["ip"], set()).add(e["mac"])
    return {ip: sorted(macs) for ip, macs in seen.items() if len(macs) > 1}


def ssh_command(client: paramiko.SSHClient, cmd: str, timeout: int) -> str:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return out


def collect(args: argparse.Namespace) -> list:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kwargs = {
        "hostname": args.device,
        "port": args.port,
        "username": args.username,
        "timeout": args.timeout,
    }
    if args.key:
        kwargs["key_filename"] = args.key
    else:
        kwargs["password"] = args.password

    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException:
        log.error("Authentication failed")
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        raw = ssh_command(client, args.command, args.timeout)
    finally:
        client.close()

    entries = parse_arp(raw)
    log.info("Parsed %d ARP entries", len(entries))

    if args.vendor_lookup:
        if not HAS_REQUESTS:
            log.warning("--vendor-lookup requires 'requests'; skipping")
        else:
            log.info("Resolving OUI vendors...")
            oui_cache: dict = {}
            for entry in entries:
                oui = entry["mac"].replace(":", "")[:6]
                if oui not in oui_cache:
                    oui_cache[oui] = vendor_for_mac(entry["mac"])
                entry["vendor"] = oui_cache[oui]

    return entries


def print_table(entries: list, dupes: dict) -> None:
    col = {"ip": 18, "mac": 20, "age": 5, "iface": 20}
    hdr = (f"{'IP Address':<{col['ip']}} {'MAC Address':<{col['mac']}} "
           f"{'Age':>{col['age']}}  {'Interface':<{col['iface']}} Vendor")
    print(hdr)
    print("-" * len(hdr))
    for e in entries:
        flag = " *** DUPLICATE IP ***" if e["ip"] in dupes else ""
        print(
            f"{e['ip']:<{col['ip']}} {e['mac']:<{col['mac']}} "
            f"{e['age']:>{col['age']}}  {e['interface']:<{col['iface']}} "
            f"{e['vendor']}{flag}"
        )
    if dupes:
        print(f"\n[!] {len(dupes)} duplicate IP address(es) detected:")
        for ip, macs in dupes.items():
            print(f"    {ip} -> {', '.join(macs)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ARP table collector with MAC vendor resolution and duplicate detection"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("-k", "--key", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument("--timeout", type=int, default=15, help="SSH timeout seconds")
    parser.add_argument(
        "--command", default="show ip arp",
        help="ARP command to run (default: 'show ip arp')"
    )
    parser.add_argument(
        "--vendor-lookup", action="store_true",
        help="Resolve MAC OUI to vendor name via macvendors.com"
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Write results to JSON file"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    if not args.key and args.password is None:
        args.password = getpass(f"Password for {args.username}@{args.device}: ")

    entries = collect(args)
    dupes = find_duplicate_ips(entries)
    print_table(entries, dupes)

    if args.output:
        payload = {
            "device": args.device,
            "command": args.command,
            "entry_count": len(entries),
            "duplicate_ips": dupes,
            "entries": entries,
        }
        with open(args.output, "w") as fh:
            json.dump(payload, fh, indent=2)
        log.info("Results saved to %s", args.output)


if __name__ == "__main__":
    main()
```