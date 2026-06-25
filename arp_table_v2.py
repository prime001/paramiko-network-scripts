ARP Anomaly Detector — Multi-device ARP cross-correlation for spoofing detection.

Collects ARP tables from multiple network devices via SSH (paramiko), aggregates
entries across all devices, and flags anomalies:
  - Same IP mapped to different MACs across devices (potential ARP spoofing)
  - Single MAC appearing on more IPs than a configurable threshold

Prerequisites:
    pip install paramiko

Usage:
    python arp_anomaly_detector.py -d 192.168.1.1 192.168.1.2 -u admin -p secret
    python arp_anomaly_detector.py -d 10.0.0.1 -u admin --key ~/.ssh/id_rsa --json
    python arp_anomaly_detector.py -d 10.0.0.1 10.0.0.2 -u admin --mac-threshold 3

Tested against: Cisco IOS, IOS-XE ("show ip arp" output format).
Exit code: 0 = clean, 1 = anomalies found or collection failure.
"""

import argparse
import getpass
import json
import logging
import re
import sys
from collections import defaultdict

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Matches: Protocol  Address  Age  Hardware Addr  Type  Interface
ARP_LINE_RE = re.compile(
    r"^\S+\s+([\d.]+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+",
    re.IGNORECASE,
)


def _ssh_run(host, username, password, key_file, command, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs = {
            "hostname": host,
            "username": username,
            "timeout": timeout,
            "look_for_keys": bool(key_file),
        }
        if key_file:
            kwargs["key_filename"] = key_file
        else:
            kwargs["password"] = password
        client.connect(**kwargs)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.debug("%s stderr: %s", host, err)
        return output
    finally:
        client.close()


def parse_arp_output(raw):
    entries = []
    for line in raw.splitlines():
        m = ARP_LINE_RE.match(line.strip())
        if m:
            entries.append({"ip": m.group(1), "mac": m.group(2).lower()})
    return entries


def collect_from_device(host, username, password, key_file, timeout):
    try:
        raw = _ssh_run(host, username, password, key_file, "show ip arp", timeout)
        entries = parse_arp_output(raw)
        log.info("%s: %d ARP entries", host, len(entries))
        return entries
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
    except paramiko.SSHException as exc:
        log.error("%s: SSH error — %s", host, exc)
    except OSError as exc:
        log.error("%s: connection error — %s", host, exc)
    return []


def detect_anomalies(all_entries, mac_ip_threshold):
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)

    for entry in all_entries:
        ip_to_macs[entry["ip"]].add(entry["mac"])
        mac_to_ips[entry["mac"]].add(entry["ip"])

    anomalies = []

    for ip, macs in sorted(ip_to_macs.items()):
        if len(macs) > 1:
            anomalies.append({
                "type": "IP_MAC_CONFLICT",
                "severity": "HIGH",
                "ip": ip,
                "macs": sorted(macs),
                "detail": f"IP {ip} maps to {len(macs)} distinct MACs — possible ARP spoofing",
            })

    for mac, ips in sorted(mac_to_ips.items()):
        if len(ips) > mac_ip_threshold:
            anomalies.append({
                "type": "MAC_MULTI_IP",
                "severity": "MEDIUM",
                "mac": mac,
                "ips": sorted(ips),
                "detail": (
                    f"MAC {mac} seen on {len(ips)} IPs "
                    f"(threshold {mac_ip_threshold})"
                ),
            })

    return anomalies


def print_report(all_entries, anomalies, devices, as_json):
    if as_json:
        print(json.dumps({"entries": all_entries, "anomalies": anomalies}, indent=2))
        return

    bar = "=" * 62
    print(f"\n{bar}")
    print(
        f"ARP Anomaly Report  |  {len(devices)} device(s)  "
        f"|  {len(all_entries)} total entries"
    )
    print(bar)

    if not anomalies:
        print("\n  [OK] No anomalies detected.\n")
    else:
        print(f"\n  [!] {len(anomalies)} anomaly(ies):\n")
        for a in anomalies:
            print(f"  [{a['severity']}] {a['detail']}")
            if a["type"] == "IP_MAC_CONFLICT":
                for mac in a["macs"]:
                    print(f"         MAC: {mac}")
            else:
                for ip in a["ips"]:
                    print(f"          IP: {ip}")
            print()

    print(f"{bar}\n")


def build_parser():
    p = argparse.ArgumentParser(
        description="Cross-correlate ARP tables across devices and flag anomalies.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--devices", nargs="+", required=True, metavar="HOST",
                   help="Device hostname(s) or IP address(es)")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None,
                   help="SSH password (prompted if omitted and no --key)")
    p.add_argument("--key", dest="key_file", metavar="PATH",
                   help="SSH private key file")
    p.add_argument("--timeout", type=int, default=30,
                   help="SSH connect/command timeout in seconds")
    p.add_argument("--mac-threshold", type=int, default=5, dest="mac_ip_threshold",
                   metavar="N",
                   help="Alert when a single MAC appears on more than N IPs")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="Emit JSON instead of human-readable output")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_file:
        password = getpass.getpass(f"SSH password for {args.username}@<devices>: ")

    all_entries = []
    for host in args.devices:
        entries = collect_from_device(
            host, args.username, password, args.key_file, args.timeout
        )
        for e in entries:
            e["source"] = host
        all_entries.extend(entries)

    if not all_entries:
        log.error("No ARP entries collected — check connectivity and credentials.")
        sys.exit(1)

    anomalies = detect_anomalies(all_entries, args.mac_ip_threshold)
    print_report(all_entries, anomalies, args.devices, args.as_json)

    sys.exit(1 if anomalies else 0)