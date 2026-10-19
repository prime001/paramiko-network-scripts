```python
"""
arp_table_v3.py - ARP Cache Monitor with Baseline Comparison

Connects to a network device via SSH, retrieves the ARP table, and compares
it against a saved baseline to detect new hosts, missing hosts, and MAC address
changes (potential ARP spoofing indicators).

Usage:
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret --save-baseline
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret --baseline baseline.json

Prerequisites:
    pip install paramiko
    Device must support 'show arp' (Cisco IOS/NX-OS) or 'show ip arp'
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_run(host, username, password, command, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.debug("stderr: %s", err)
        return output
    finally:
        client.close()


def parse_arp_table(raw):
    """
    Parse 'show arp' output into {ip: mac} mapping.
    Handles Cisco IOS format: Protocol  Address  Age  Hardware Addr  Type  Interface
    """
    entries = {}
    pattern = re.compile(
        r"Internet\s+"
        r"((?:\d{1,3}\.){3}\d{1,3})\s+"
        r"\S+\s+"
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
    )
    for line in raw.splitlines():
        m = pattern.search(line)
        if m:
            ip, mac = m.group(1), m.group(2).lower()
            entries[ip] = mac
    return entries


def normalize_mac(mac):
    """Convert any common MAC format to xx:xx:xx:xx:xx:xx."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        return mac
    return ":".join(digits[i:i+2] for i in range(0, 12, 2))


def compare_arp(baseline, current):
    new_hosts = {}
    removed_hosts = {}
    mac_changes = {}

    for ip, mac in current.items():
        if ip not in baseline:
            new_hosts[ip] = mac
        elif normalize_mac(baseline[ip]) != normalize_mac(mac):
            mac_changes[ip] = {"old": baseline[ip], "new": mac}

    for ip, mac in baseline.items():
        if ip not in current:
            removed_hosts[ip] = mac

    return new_hosts, removed_hosts, mac_changes


def find_duplicate_macs(entries):
    """Return MACs that appear for more than one IP (shared MAC / HSRP exception)."""
    mac_to_ips = {}
    for ip, mac in entries.items():
        norm = normalize_mac(mac)
        mac_to_ips.setdefault(norm, []).append(ip)
    return {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}


def print_table(entries):
    if not entries:
        print("  (empty)")
        return
    width = max(len(ip) for ip in entries)
    for ip in sorted(entries):
        print(f"  {ip:<{width}}  {normalize_mac(entries[ip])}")


def main():
    parser = argparse.ArgumentParser(
        description="ARP cache monitor with baseline comparison"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--command", default="show arp", help="ARP command to run")
    parser.add_argument("--baseline", default="arp_baseline.json",
                        help="Baseline JSON file path")
    parser.add_argument("--save-baseline", action="store_true",
                        help="Save current ARP table as new baseline")
    args = parser.parse_args()

    log.info("Connecting to %s", args.device)
    try:
        raw = ssh_run(args.device, args.username, args.password,
                      args.command, port=args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as e:
        log.error("Connection failed: %s", e)
        sys.exit(1)

    current = parse_arp_table(raw)
    if not current:
        log.warning("No ARP entries parsed — check command output format")
        print(raw[:500])
        sys.exit(1)

    log.info("Parsed %d ARP entries", len(current))

    if args.save_baseline:
        Path(args.baseline).write_text(json.dumps(current, indent=2))
        log.info("Baseline saved to %s", args.baseline)
        print(f"\nBaseline saved: {len(current)} entries -> {args.baseline}")
        return

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        print(f"\nNo baseline found at {args.baseline}. Run with --save-baseline first.")
        print(f"\nCurrent ARP table ({len(current)} entries):")
        print_table(current)
        sys.exit(0)

    baseline = json.loads(baseline_path.read_text())
    log.info("Loaded baseline with %d entries from %s", len(baseline), args.baseline)

    new_hosts, removed_hosts, mac_changes = compare_arp(baseline, current)
    duplicates = find_duplicate_macs(current)

    print(f"\n=== ARP Monitor: {args.device} ===")
    print(f"Baseline: {len(baseline)} entries  |  Current: {len(current)} entries\n")

    if new_hosts:
        print(f"[+] NEW HOSTS ({len(new_hosts)}):")
        print_table(new_hosts)
    else:
        print("[+] New hosts: none")

    if removed_hosts:
        print(f"\n[-] REMOVED HOSTS ({len(removed_hosts)}):")
        print_table(removed_hosts)
    else:
        print("[-] Removed hosts: none")

    if mac_changes:
        print(f"\n[!] MAC CHANGES ({len(mac_changes)}) — possible ARP spoofing:")
        for ip, chg in sorted(mac_changes.items()):
            print(f"  {ip}  {normalize_mac(chg['old'])} -> {normalize_mac(chg['new'])}")
    else:
        print("[!] MAC changes: none")

    if duplicates:
        print(f"\n[D] DUPLICATE MACs ({len(duplicates)}) — may indicate HSRP/VRRP or conflict:")
        for mac, ips in sorted(duplicates.items()):
            print(f"  {mac}  -> {', '.join(sorted(ips))}")
    else:
        print("[D] Duplicate MACs: none")

    if not any([new_hosts, removed_hosts, mac_changes]):
        print("\nResult: ARP table matches baseline exactly.")
    else:
        total = len(new_hosts) + len(removed_hosts) + len(mac_changes)
        print(f"\nResult: {total} change(s) detected since baseline.")


if __name__ == "__main__":
    main()
```