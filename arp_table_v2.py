```python
"""
arp_anomaly_detector.py - ARP Table Anomaly Detection via Paramiko

Purpose:
    Retrieves the ARP table from a Cisco IOS/IOS-XE device and performs
    anomaly analysis: duplicate IP-to-MAC mappings (potential ARP spoofing),
    duplicate MAC-to-IP mappings (flapping or misconfiguration), and
    incomplete entries. Optionally saves a baseline and diffs subsequent
    runs to surface new, removed, or changed entries.

Usage:
    python arp_anomaly_detector.py -d 192.168.1.1 -u admin
    python arp_anomaly_detector.py -d 192.168.1.1 -u admin --save-baseline baseline.json
    python arp_anomaly_detector.py -d 192.168.1.1 -u admin --compare-baseline baseline.json
    python arp_anomaly_detector.py -d 192.168.1.1 -u admin --json

Prerequisites:
    pip install paramiko
    Device must support 'show ip arp' (Cisco IOS/IOS-XE)
    SSH must be enabled on the target device

Exit codes:
    0 - clean (no anomalies or only LOW severity)
    1 - runtime error
    2 - HIGH severity anomaly detected (suitable for monitoring pipelines)
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from getpass import getpass
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_ARP_RE = re.compile(
    r"^(?P<protocol>\S+)\s+"
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"(?P<age>\S+)\s+"
    r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|-)\s+"
    r"(?P<encap>\S+)\s+"
    r"(?P<iface>\S+)",
    re.IGNORECASE,
)


def ssh_run(host, port, username, password, command, timeout):
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
            log.warning("stderr from device: %s", err)
        return output
    finally:
        client.close()


def parse_arp_table(raw):
    entries = []
    for line in raw.splitlines():
        m = _ARP_RE.match(line.strip())
        if not m:
            continue
        entries.append({
            "ip": m.group("ip"),
            "mac": m.group("mac").lower(),
            "age": m.group("age"),
            "interface": m.group("iface"),
            "incomplete": m.group("mac") == "-",
        })
    return entries


def analyze(entries):
    anomalies = []
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)

    for e in entries:
        if e["incomplete"]:
            anomalies.append({
                "severity": "LOW",
                "type": "INCOMPLETE",
                "detail": f"Incomplete ARP entry for {e['ip']} on {e['interface']}",
            })
            continue
        ip_to_macs[e["ip"]].add(e["mac"])
        mac_to_ips[e["mac"]].add(e["ip"])

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            anomalies.append({
                "severity": "HIGH",
                "type": "IP_CONFLICT",
                "detail": f"{ip} resolves to multiple MACs: {', '.join(sorted(macs))} — possible ARP spoofing",
            })

    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            anomalies.append({
                "severity": "MEDIUM",
                "type": "MAC_CONFLICT",
                "detail": f"{mac} appears on multiple IPs: {', '.join(sorted(ips))}",
            })

    return anomalies


def diff_baseline(current_entries, baseline_path):
    with open(baseline_path) as f:
        baseline = json.load(f)

    base_map = {e["ip"]: e["mac"] for e in baseline if not e["incomplete"]}
    curr_map = {e["ip"]: e["mac"] for e in current_entries if not e["incomplete"]}
    changes = []

    for ip, mac in curr_map.items():
        if ip not in base_map:
            changes.append({"change": "NEW", "ip": ip, "mac": mac})
        elif base_map[ip] != mac:
            changes.append({
                "change": "MAC_CHANGED",
                "ip": ip,
                "old_mac": base_map[ip],
                "new_mac": mac,
            })

    for ip, mac in base_map.items():
        if ip not in curr_map:
            changes.append({"change": "REMOVED", "ip": ip, "mac": mac})

    return changes


def print_report(entries, anomalies, changes, use_json):
    report = {
        "total_entries": len(entries),
        "incomplete_count": sum(1 for e in entries if e["incomplete"]),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }
    if changes is not None:
        report["baseline_changes"] = changes

    if use_json:
        report["entries"] = entries
        print(json.dumps(report, indent=2))
        return

    print(f"\nARP Table Summary: {report['total_entries']} entries "
          f"({report['incomplete_count']} incomplete)")

    if anomalies:
        print(f"\nANOMALIES ({len(anomalies)}):")
        for a in sorted(anomalies, key=lambda x: x["severity"]):
            print(f"  [{a['severity']:6s}] {a['type']}: {a['detail']}")
    else:
        print("\nNo anomalies detected.")

    if changes is not None:
        if changes:
            print(f"\nBASELINE DIFF ({len(changes)} changes):")
            for c in changes:
                if c["change"] == "NEW":
                    print(f"  + {c['ip']:18s}  {c['mac']}  (new)")
                elif c["change"] == "REMOVED":
                    print(f"  - {c['ip']:18s}  {c['mac']}  (removed)")
                else:
                    print(f"  ! {c['ip']:18s}  {c['old_mac']} -> {c['new_mac']}")
        else:
            print("\nBaseline diff: no changes.")


def main():
    parser = argparse.ArgumentParser(
        description="Detect ARP anomalies on Cisco IOS devices via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--command", default="show ip arp", help="ARP command override")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--save-baseline", metavar="FILE", help="Save current ARP table as JSON baseline")
    parser.add_argument("--compare-baseline", metavar="FILE", help="Diff current table against baseline")
    parser.add_argument("--json", action="store_true", dest="use_json", help="Emit JSON output")
    args = parser.parse_args()

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        raw = ssh_run(args.device, args.port, args.username, password, args.command, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    entries = parse_arp_table(raw)
    if not entries:
        log.error("No ARP entries parsed — verify device type and command")
        sys.exit(1)

    log.info("Parsed %d ARP entries", len(entries))

    if args.save_baseline:
        Path(args.save_baseline).write_text(json.dumps(entries, indent=2))
        log.info("Baseline saved to %s", args.save_baseline)

    anomalies = analyze(entries)

    changes = None
    if args.compare_baseline:
        if not Path(args.compare_baseline).exists():
            log.error("Baseline file not found: %s", args.compare_baseline)
            sys.exit(1)
        changes = diff_baseline(entries, args.compare_baseline)

    print_report(entries, anomalies, changes, args.use_json)

    if any(a["severity"] == "HIGH" for a in anomalies):
        sys.exit(2)


if __name__ == "__main__":
    main()
```