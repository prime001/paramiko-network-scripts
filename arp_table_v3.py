arp_table_monitor.py - ARP Table Change Monitor

Purpose:
    Retrieves the ARP table from a network device, saves it as a JSON snapshot,
    and on subsequent runs compares against the saved baseline to identify:
    - New hosts that appeared since the last snapshot
    - Hosts that disappeared from the network
    - IP-to-MAC binding changes (potential ARP spoofing indicator)

Usage:
    python arp_table_monitor.py -d 192.168.1.1 -u admin -p secret
    python arp_table_monitor.py -d 192.168.1.1 -u admin -p secret --save-baseline
    python arp_table_monitor.py -d 192.168.1.1 -u admin -p secret --baseline /tmp/snap.json
    python arp_table_monitor.py -d 192.168.1.1 -u admin -p secret --no-compare

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Tested against Cisco IOS/IOS-XE. Adjust parse_arp_table() for other vendors.
"""

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

DEFAULT_BASELINE = "arp_baseline.json"
CONNECT_TIMEOUT = 15


def ssh_connect(host, username, password, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as e:
        logger.error("SSH error connecting to %s: %s", host, e)
        raise
    except OSError as e:
        logger.error("Network error connecting to %s: %s", host, e)
        raise


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        logger.debug("stderr: %s", err)
    return output


def parse_arp_table(output):
    entries = {}
    # Cisco IOS: Internet  10.0.0.1  -  aabb.cc00.0100  ARPA  Gi0/0
    pattern = re.compile(
        r"Internet\s+([\d.]+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
        re.IGNORECASE,
    )
    for match in pattern.finditer(output):
        ip, mac = match.group(1), match.group(2).lower()
        entries[ip] = mac
    return entries


def load_baseline(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Could not load baseline %s: %s", path, e)
        return None


def save_baseline(path, entries, device):
    snapshot = {
        "device": device,
        "timestamp": datetime.now().isoformat(),
        "entries": entries,
    }
    try:
        with open(path, "w") as f:
            json.dump(snapshot, f, indent=2)
        logger.info("Baseline saved to %s (%d entries)", path, len(entries))
    except OSError as e:
        logger.error("Failed to save baseline: %s", e)
        raise


def compare_arp(current, baseline_entries):
    new_hosts = {ip: mac for ip, mac in current.items() if ip not in baseline_entries}
    removed_hosts = {ip: mac for ip, mac in baseline_entries.items() if ip not in current}
    mac_changes = {
        ip: {"old": baseline_entries[ip], "new": current[ip]}
        for ip in current
        if ip in baseline_entries and current[ip] != baseline_entries[ip]
    }
    return new_hosts, removed_hosts, mac_changes


def print_comparison(new_hosts, removed_hosts, mac_changes, baseline_ts):
    print(f"\nARP Change Report  (baseline: {baseline_ts})")
    print("=" * 60)

    if new_hosts:
        print(f"\n[+] NEW hosts ({len(new_hosts)}):")
        for ip, mac in sorted(new_hosts.items()):
            print(f"    {ip:<18} {mac}")
    else:
        print("\n[+] No new hosts")

    if removed_hosts:
        print(f"\n[-] REMOVED hosts ({len(removed_hosts)}):")
        for ip, mac in sorted(removed_hosts.items()):
            print(f"    {ip:<18} {mac}")
    else:
        print("\n[-] No removed hosts")

    if mac_changes:
        print(f"\n[!] MAC CHANGES ({len(mac_changes)}) — possible ARP spoofing:")
        for ip, change in sorted(mac_changes.items()):
            print(f"    {ip:<18} {change['old']}  ->  {change['new']}")
    else:
        print("\n[!] No MAC binding changes")

    print()


def print_arp_table(entries, device):
    print(f"\nARP Table — {device}")
    print("=" * 60)
    print(f"{'IP Address':<18} {'MAC Address'}")
    print("-" * 40)
    for ip, mac in sorted(entries.items()):
        print(f"{ip:<18} {mac}")
    print(f"\nTotal: {len(entries)} entries")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor ARP table changes and detect MAC binding shifts"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--baseline",
        default=DEFAULT_BASELINE,
        help=f"Baseline JSON file path (default: {DEFAULT_BASELINE})",
    )
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Overwrite the baseline file with the current ARP table",
    )
    parser.add_argument(
        "--no-compare",
        action="store_true",
        help="Skip baseline comparison; just display the current ARP table",
    )
    args = parser.parse_args()

    try:
        logger.info("Connecting to %s", args.device)
        client = ssh_connect(args.device, args.username, args.password, args.port)
    except Exception:
        sys.exit(1)

    try:
        logger.info("Fetching ARP table")
        output = run_command(client, "show arp")
        current = parse_arp_table(output)

        if not current:
            logger.warning(
                "No ARP entries parsed — check device type or output format"
            )

        print_arp_table(current, args.device)

        if args.save_baseline:
            save_baseline(args.baseline, current, args.device)
            return

        if not args.no_compare:
            baseline_data = load_baseline(args.baseline)
            if baseline_data is None:
                logger.info(
                    "No baseline found at %s — run with --save-baseline to create one",
                    args.baseline,
                )
            else:
                baseline_entries = baseline_data.get("entries", {})
                baseline_ts = baseline_data.get("timestamp", "unknown")
                new_hosts, removed_hosts, mac_changes = compare_arp(
                    current, baseline_entries
                )
                print_comparison(new_hosts, removed_hosts, mac_changes, baseline_ts)
                if mac_changes:
                    logger.warning(
                        "%d MAC binding change(s) detected — investigate for ARP spoofing",
                        len(mac_changes),
                    )
    finally:
        client.close()
        logger.info("Connection closed")


if __name__ == "__main__":
    main()