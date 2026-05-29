arp_table_v3.py - Multi-Device ARP Cross-Reference and Network Audit Tool

Queries ARP tables across multiple network devices simultaneously to build a
fleet-wide MAC-to-IP mapping. Useful for locating a specific host by MAC or IP
across a large network, detecting ARP inconsistencies (same IP resolving to
different MACs on different devices, indicating possible ARP spoofing or
misconfiguration), and producing a consolidated ARP inventory from the network core.

Usage:
    # Search for a MAC across all core switches
    python arp_table_v3.py -f devices.txt -u admin --search-mac 00:1a:2b:3c:4d:5e

    # Search for an IP address
    python arp_table_v3.py -d 10.0.0.1,10.0.0.2,10.0.0.3 -u admin --search-ip 192.168.1.50

    # Full audit: find ARP inconsistencies across devices
    python arp_table_v3.py -f devices.txt -u admin --audit

    # Export consolidated ARP table to CSV
    python arp_table_v3.py -f devices.txt -u admin --csv arp_audit.csv

Prerequisites:
    pip install paramiko
    Devices reachable via SSH; account needs privilege to run 'show arp'.
    devices.txt: one hostname or IP per line, lines starting with # are ignored.
"""

import argparse
import csv
import getpass
import logging
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

ARP_PATTERN = re.compile(
    r"^(\S+)\s+([\d.]+)\s+(\d+|-)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|-)\s+(\S+)\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class ArpEntry:
    device: str
    ip_address: str
    mac_address: str
    age: str
    interface: str
    entry_type: str


@dataclass
class DeviceResult:
    device: str
    entries: List[ArpEntry] = field(default_factory=list)
    error: Optional[str] = None


def collect_arp(device: str, username: str, password: str, port: int) -> DeviceResult:
    result = DeviceResult(device=device)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=device, port=port, username=username, password=password,
            timeout=15, look_for_keys=False, allow_agent=False,
        )
        _, stdout, _ = client.exec_command("show arp", timeout=30)
        raw = stdout.read().decode("utf-8", errors="replace")
        for m in ARP_PATTERN.finditer(raw):
            result.entries.append(ArpEntry(
                device=device,
                ip_address=m.group(2),
                mac_address=m.group(4).lower(),
                age=m.group(3),
                interface=m.group(6),
                entry_type=m.group(5),
            ))
        log.info("%s: %d entries collected", device, len(result.entries))
    except paramiko.AuthenticationException:
        result.error = "Authentication failed"
        log.error("%s: authentication failed", device)
    except (paramiko.SSHException, OSError) as exc:
        result.error = str(exc)
        log.error("%s: connection error: %s", device, exc)
    finally:
        client.close()
    return result


def collect_all(devices: List[str], username: str, password: str, port: int,
                workers: int = 10) -> List[DeviceResult]:
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(collect_arp, d, username, password, port): d for d in devices}
        for future in as_completed(futures):
            results.append(future.result())
    return results


def build_index(results: List[DeviceResult]) -> Tuple[
    Dict[str, List[ArpEntry]],
    Dict[str, List[ArpEntry]],
]:
    mac_index: Dict[str, List[ArpEntry]] = defaultdict(list)
    ip_index: Dict[str, List[ArpEntry]] = defaultdict(list)
    for r in results:
        for e in r.entries:
            if e.mac_address != "-":
                mac_index[e.mac_address].append(e)
            ip_index[e.ip_address].append(e)
    return mac_index, ip_index


def find_host(query: str, mac_index: Dict, ip_index: Dict) -> None:
    norm = query.lower().replace(":", "").replace("-", "").replace(".", "")
    hits = []
    for mac, entries in mac_index.items():
        if mac.replace(".", "") == norm:
            hits.extend(entries)
    if not hits:
        for ip, entries in ip_index.items():
            if ip == query:
                hits.extend(entries)
    if not hits:
        print(f"No ARP entry found for: {query}")
        return
    print(f"Found on {len({h.device for h in hits})} device(s):")
    for e in hits:
        print(f"  {e.device:<20}  IP: {e.ip_address:<18}  MAC: {e.mac_address}  "
              f"Age: {e.age:>5}  Iface: {e.interface}")


def audit_inconsistencies(mac_index: Dict, ip_index: Dict) -> None:
    print("\n=== ARP Inconsistency Audit ===")
    found = False

    for ip, entries in ip_index.items():
        macs = {e.mac_address for e in entries if e.mac_address != "-"}
        if len(macs) > 1:
            print(f"[CONFLICT] IP {ip} resolves to multiple MACs across devices:")
            for e in entries:
                print(f"  {e.device:<20}  MAC: {e.mac_address}  Iface: {e.interface}")
            found = True

    for mac, entries in mac_index.items():
        ips = {e.ip_address for e in entries}
        if len(ips) > 1:
            print(f"[MULTI-IP] MAC {mac} appears with multiple IPs (possible move or spoofing):")
            for e in entries:
                print(f"  {e.device:<20}  IP: {e.ip_address:<18}  Iface: {e.interface}")
            found = True

    if not found:
        print("No inconsistencies detected.")


def export_csv(results: List[DeviceResult], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["device", "ip_address", "mac_address", "age", "interface", "type"])
        for r in results:
            for e in r.entries:
                writer.writerow([e.device, e.ip_address, e.mac_address,
                                  e.age, e.interface, e.entry_type])
    log.info("Exported to %s", path)


def load_devices(path: str) -> List[str]:
    try:
        with open(path) as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except OSError as exc:
        log.error("Cannot read device file: %s", exc)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-device ARP cross-reference and inconsistency audit."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-d", "--devices", help="Comma-separated list of device IPs/hostnames")
    src.add_argument("-f", "--file", metavar="FILE", help="File with one device per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--workers", type=int, default=10, help="Concurrent SSH threads (default: 10)")
    parser.add_argument("--search-mac", metavar="MAC", help="Find this MAC across all devices")
    parser.add_argument("--search-ip", metavar="IP", help="Find this IP across all devices")
    parser.add_argument("--audit", action="store_true", help="Report ARP inconsistencies across devices")
    parser.add_argument("--csv", metavar="FILE", help="Export full ARP table to CSV")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if not any([args.search_mac, args.search_ip, args.audit, args.csv]):
        parser.error("Specify at least one action: --search-mac, --search-ip, --audit, or --csv")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    devices = args.devices.split(",") if args.devices else load_devices(args.file)
    devices = [d.strip() for d in devices if d.strip()]
    if not devices:
        log.error("No devices specified.")
        sys.exit(1)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    log.info("Querying %d device(s) with %d workers...", len(devices), args.workers)
    results = collect_all(devices, args.username, password, args.port, args.workers)

    failed = [r.device for r in results if r.error]
    if failed:
        log.warning("Failed to reach %d device(s): %s", len(failed), ", ".join(failed))

    mac_index, ip_index = build_index(results)
    total = sum(len(r.entries) for r in results)
    log.info("Total ARP entries collected: %d", total)

    if args.search_mac:
        find_host(args.search_mac, mac_index, ip_index)
    if args.search_ip:
        find_host(args.search_ip, mac_index, ip_index)
    if args.audit:
        audit_inconsistencies(mac_index, ip_index)
    if args.csv:
        export_csv(results, args.csv)


if __name__ == "__main__":
    main()