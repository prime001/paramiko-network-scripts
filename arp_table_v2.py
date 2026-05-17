```python
"""
arp_anomaly_detector.py - ARP table anomaly detection via Paramiko

Purpose:
    Connects to a network device, retrieves the ARP table, and analyzes
    entries for operational anomalies: duplicate IP addresses (IP conflicts
    or ARP spoofing), duplicate MACs (one host advertising multiple IPs),
    and incomplete entries. Optionally diffs against a saved baseline to
    surface new or removed hosts.

Usage:
    python arp_anomaly_detector.py -d 192.168.1.1 -u admin -p secret
    python arp_anomaly_detector.py -d 10.0.0.1 -u admin -k ~/.ssh/id_rsa \
        --save-baseline baseline.json
    python arp_anomaly_detector.py -d 10.0.0.1 -u admin -p secret \
        --baseline baseline.json --csv report.csv

Prerequisites:
    pip install paramiko
    SSH access to target device with privilege to run 'show arp'.
    Tested against Cisco IOS/IOS-XE. Exits non-zero when anomalies are found
    (useful for scripted alerting pipelines).
"""

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


def ssh_run(host, port, username, password, key_file, command, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host, port=port, username=username,
        timeout=timeout, look_for_keys=False, allow_agent=False,
    )
    if key_file:
        kwargs["key_filename"] = key_file
        kwargs["look_for_keys"] = True
    else:
        kwargs["password"] = password
    try:
        client.connect(**kwargs)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode()
        err = stderr.read().decode().strip()
        if err:
            log.debug("stderr: %s", err)
        return output
    finally:
        client.close()


def parse_cisco_arp(raw):
    """Parse 'show arp' from Cisco IOS/IOS-XE into a list of dicts."""
    entries = []
    pattern = re.compile(
        r"^Internet\s+"
        r"(\d+\.\d+\.\d+\.\d+)\s+"
        r"(\d+|-)\s+"
        r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|Incomplete)\s+"
        r"(\S+)\s*(\S+)?",
        re.IGNORECASE,
    )
    for line in raw.splitlines():
        m = pattern.match(line.strip())
        if m:
            entries.append({
                "ip": m.group(1),
                "age": m.group(2),
                "mac": m.group(3).lower(),
                "type": m.group(4),
                "interface": m.group(5) or "",
            })
    return entries


def detect_anomalies(entries):
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)
    incomplete = []

    for e in entries:
        if e["mac"] == "incomplete":
            incomplete.append(e["ip"])
            continue
        ip_to_macs[e["ip"]].add(e["mac"])
        mac_to_ips[e["mac"]].add(e["ip"])

    return {
        "duplicate_ips": {ip: list(macs) for ip, macs in ip_to_macs.items() if len(macs) > 1},
        "duplicate_macs": {mac: list(ips) for mac, ips in mac_to_ips.items() if len(ips) > 1},
        "incomplete": incomplete,
    }


def diff_baseline(current, baseline_path):
    path = Path(baseline_path)
    if not path.exists():
        log.warning("Baseline %s not found; skipping diff", baseline_path)
        return None
    baseline = json.loads(path.read_text())
    base_set = {(e["ip"], e["mac"]) for e in baseline}
    curr_set = {(e["ip"], e["mac"]) for e in current if e["mac"] != "incomplete"}
    return {
        "new": [{"ip": ip, "mac": mac} for ip, mac in sorted(curr_set - base_set)],
        "removed": [{"ip": ip, "mac": mac} for ip, mac in sorted(base_set - curr_set)],
    }


def print_report(entries, anomalies, diff=None):
    print(f"\n{'='*60}\nARP Table — {len(entries)} entries\n{'='*60}")
    for e in entries:
        flag = " [INCOMPLETE]" if e["mac"] == "incomplete" else ""
        print(f"  {e['ip']:<18} {e['mac']:<20} {e['interface']}{flag}")

    print(f"\n{'='*60}\nAnomaly Report\n{'='*60}")

    if anomalies["duplicate_ips"]:
        print(f"\n[!] Duplicate IPs — possible IP conflict or ARP spoofing ({len(anomalies['duplicate_ips'])}):")
        for ip, macs in anomalies["duplicate_ips"].items():
            print(f"    {ip} -> {', '.join(macs)}")
    else:
        print("\n[OK] No duplicate IP addresses")

    if anomalies["duplicate_macs"]:
        print(f"\n[!] Duplicate MACs — one host on multiple IPs ({len(anomalies['duplicate_macs'])}):")
        for mac, ips in anomalies["duplicate_macs"].items():
            print(f"    {mac} -> {', '.join(ips)}")
    else:
        print("\n[OK] No duplicate MAC addresses")

    if anomalies["incomplete"]:
        print(f"\n[!] Incomplete entries ({len(anomalies['incomplete'])}):")
        for ip in anomalies["incomplete"]:
            print(f"    {ip}")
    else:
        print("\n[OK] No incomplete ARP entries")

    if diff is not None:
        print(f"\n{'='*60}\nBaseline Diff\n{'='*60}")
        if diff["new"]:
            print(f"\n[+] New entries ({len(diff['new'])}):")
            for e in diff["new"]:
                print(f"    {e['ip']:<18} {e['mac']}")
        if diff["removed"]:
            print(f"\n[-] Removed entries ({len(diff['removed'])}):")
            for e in diff["removed"]:
                print(f"    {e['ip']:<18} {e['mac']}")
        if not diff["new"] and not diff["removed"]:
            print("\n[OK] ARP table matches baseline exactly")


def build_parser():
    p = argparse.ArgumentParser(
        description="Fetch ARP table and detect anomalies (duplicate IPs/MACs, incomplete entries)"
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default="", help="SSH password")
    p.add_argument("-k", "--key-file", help="Path to SSH private key")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--command", default="show arp", help="ARP command to run")
    p.add_argument("--csv", metavar="FILE", help="Export ARP table to CSV")
    p.add_argument("--baseline", metavar="FILE", help="Compare against saved baseline JSON")
    p.add_argument("--save-baseline", metavar="FILE", help="Save current table as baseline JSON")
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        import getpass
        args.password = getpass.getpass("SSH password: ")

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        raw = ssh_run(
            args.device, args.port, args.username, args.password,
            args.key_file, args.command, args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    entries = parse_cisco_arp(raw)
    if not entries:
        log.error("No ARP entries parsed — check device type or command output")
        log.debug("Raw output:\n%s", raw)
        sys.exit(1)

    log.info("Parsed %d ARP entries", len(entries))
    anomalies = detect_anomalies(entries)
    diff = diff_baseline(entries, args.baseline) if args.baseline else None
    print_report(entries, anomalies, diff)

    if args.save_baseline:
        clean = [e for e in entries if e["mac"] != "incomplete"]
        Path(args.save_baseline).write_text(json.dumps(clean, indent=2))
        log.info("Baseline saved: %s (%d entries)", args.save_baseline, len(clean))

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "age", "mac", "type", "interface"])
            writer.writeheader()
            writer.writerows(entries)
        log.info("CSV written to %s", args.csv)

    has_critical = bool(anomalies["duplicate_ips"] or anomalies["duplicate_macs"])
    sys.exit(1 if has_critical else 0)
```