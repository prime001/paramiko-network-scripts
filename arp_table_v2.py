```python
"""
ARP Table Cross-Device Reconciliation

Purpose:
    Collects ARP tables from multiple Cisco IOS/NX-OS devices and cross-references
    entries to detect MAC conflicts (same IP mapped to different MACs across devices,
    a potential ARP spoofing indicator) and IP conflicts (same MAC claiming multiple
    IPs, indicating a duplicate-IP or misconfigured host condition).

Usage:
    python arp_reconcile.py -d 192.168.1.1,192.168.1.2 -u admin -p secret
    python arp_reconcile.py --device-file routers.txt -u admin --key ~/.ssh/id_rsa
    python arp_reconcile.py -d 10.0.0.1,10.0.0.2 -u admin -p secret --format json

Prerequisites:
    pip install paramiko
    SSH access to each device; privilege level sufficient to run 'show ip arp'.
"""

import argparse
import getpass
import json
import logging
import re
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# Matches Cisco "show ip arp" lines: IP, age, MAC, type, interface
_ARP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+"
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
)


def _normalize_mac(cisco_mac: str) -> str:
    digits = cisco_mac.replace(".", "").lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _connect(host: str, username: str, password: Optional[str],
             key_path: Optional[str], port: int, timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: Dict = {
        "hostname": host, "port": port, "username": username,
        "timeout": timeout, "allow_agent": False, "look_for_keys": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
        kwargs["look_for_keys"] = True
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def fetch_arp_entries(host: str, username: str, password: Optional[str],
                      key_path: Optional[str], port: int,
                      timeout: int) -> List[Tuple[str, str]]:
    """Return (ip, normalized_mac) pairs from 'show ip arp' on *host*."""
    try:
        client = _connect(host, username, password, key_path, port, timeout)
    except Exception as exc:
        logger.error("%-20s connection failed: %s", host, exc)
        return []

    entries: List[Tuple[str, str]] = []
    try:
        _, stdout, _ = client.exec_command("show ip arp", timeout=timeout)
        for match in _ARP_RE.finditer(stdout.read().decode(errors="replace")):
            entries.append((match.group(1), _normalize_mac(match.group(2))))
        logger.info("%-20s %d ARP entries collected", host, len(entries))
    except Exception as exc:
        logger.error("%-20s command failed: %s", host, exc)
    finally:
        client.close()
    return entries


def reconcile(device_arps: Dict[str, List[Tuple[str, str]]]) -> Dict:
    ip_mac_map: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    mac_ip_map: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

    for device, entries in device_arps.items():
        for ip, mac in entries:
            ip_mac_map[ip][mac].append(device)
            mac_ip_map[mac][ip].append(device)

    mac_conflicts = {
        ip: dict(macs)
        for ip, macs in ip_mac_map.items()
        if len(macs) > 1
    }
    ip_conflicts = {
        mac: dict(ips)
        for mac, ips in mac_ip_map.items()
        if len(ips) > 1
    }

    return {
        "summary": {
            "devices_queried": len(device_arps),
            "devices_reachable": sum(1 for v in device_arps.values() if v),
            "total_arp_entries": sum(len(v) for v in device_arps.values()),
            "mac_conflicts": len(mac_conflicts),
            "ip_conflicts": len(ip_conflicts),
        },
        "mac_conflicts": mac_conflicts,
        "ip_conflicts": ip_conflicts,
    }


def _print_table(results: Dict) -> None:
    s = results["summary"]
    print(f"\nDevices queried  : {s['devices_queried']}  "
          f"(reachable: {s['devices_reachable']})")
    print(f"Total ARP entries: {s['total_arp_entries']}")
    print(f"MAC conflicts    : {s['mac_conflicts']}")
    print(f"IP conflicts     : {s['ip_conflicts']}")

    if results["mac_conflicts"]:
        print("\n[MAC CONFLICTS] Same IP -> different MACs (possible ARP spoofing)")
        for ip, mac_map in sorted(results["mac_conflicts"].items()):
            print(f"  {ip}")
            for mac, devices in mac_map.items():
                print(f"    {mac}  on: {', '.join(sorted(devices))}")

    if results["ip_conflicts"]:
        print("\n[IP CONFLICTS] Same MAC -> multiple IPs (possible duplicate IP)")
        for mac, ip_map in sorted(results["ip_conflicts"].items()):
            print(f"  {mac}")
            for ip, devices in ip_map.items():
                print(f"    {ip}  on: {', '.join(sorted(devices))}")

    if not results["mac_conflicts"] and not results["ip_conflicts"]:
        print("\nNo conflicts detected across queried devices.")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Cross-device ARP reconciliation for conflict detection."
    )
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("-d", "--devices",
                     help="Comma-separated device IPs or hostnames")
    grp.add_argument("--device-file",
                     help="Text file with one device per line (# = comment)")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", default=None)
    p.add_argument("--key", dest="key_path", default=None,
                   help="Path to SSH private key file")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=30,
                   help="SSH connect/command timeout in seconds (default: 30)")
    p.add_argument("--format", choices=["table", "json"], default="table")
    p.add_argument("--debug", action="store_true")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_path:
        args.password = getpass.getpass("SSH password: ")

    if args.devices:
        hosts = [h.strip() for h in args.devices.split(",") if h.strip()]
    else:
        try:
            with open(args.device_file) as fh:
                hosts = [
                    ln.strip()
                    for ln in fh
                    if ln.strip() and not ln.startswith("#")
                ]
        except OSError as exc:
            logger.error("Cannot read device file: %s", exc)
            sys.exit(1)

    if not hosts:
        logger.error("No devices specified.")
        sys.exit(1)

    device_arps: Dict[str, List[Tuple[str, str]]] = {}
    for host in hosts:
        device_arps[host] = fetch_arp_entries(
            host, args.username, args.password, args.key_path,
            args.port, args.timeout,
        )

    if not any(device_arps.values()):
        logger.error("No ARP data collected from any device.")
        sys.exit(1)

    results = reconcile(device_arps)

    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        _print_table(results)
```