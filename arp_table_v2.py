```python
"""
arp_anomaly_detector.py — ARP Table Security Analyzer

Connects to a Cisco IOS/IOS-XE device via SSH, retrieves the ARP table,
and detects anomalies indicative of ARP spoofing or misconfiguration:
duplicate IP-to-MAC mappings, one MAC claiming multiple IPs (gratuitous
ARP abuse), and stale INCOMPLETE entries.

Prerequisites:
    pip install paramiko

Usage:
    python arp_anomaly_detector.py -d 192.168.1.1 -u admin -p secret
    python arp_anomaly_detector.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python arp_anomaly_detector.py -d 192.168.1.1 -u admin -p secret --vrf MGMT --json
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

ARP_RE = re.compile(
    r"^(?:Internet)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<age>\d+|-)\s+"
    r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|Incomplete)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<iface>\S+)",
    re.IGNORECASE,
)


def connect(host, port, username, password, key_path, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command):
    _, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return out


def parse_arp(raw):
    entries = []
    for line in raw.splitlines():
        m = ARP_RE.match(line.strip())
        if m:
            entries.append(m.groupdict())
    return entries


def detect_anomalies(entries):
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)
    incomplete = []

    for e in entries:
        ip, mac = e["ip"], e["mac"].lower()
        if mac == "incomplete":
            incomplete.append(e)
            continue
        ip_to_macs[ip].add(mac)
        mac_to_ips[mac].add(ip)

    anomalies = []

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            anomalies.append({
                "type": "DUPLICATE_IP",
                "severity": "HIGH",
                "detail": f"{ip} maps to multiple MACs: {', '.join(sorted(macs))}",
            })

    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            anomalies.append({
                "type": "MAC_CLAIMING_MULTIPLE_IPS",
                "severity": "MEDIUM",
                "detail": f"{mac} seen on IPs: {', '.join(sorted(ips))}",
            })

    for e in incomplete:
        anomalies.append({
            "type": "INCOMPLETE_ENTRY",
            "severity": "LOW",
            "detail": f"{e['ip']} on {e['iface']} — no MAC resolved (host unreachable or transient)",
        })

    return anomalies


def print_table(entries, anomalies):
    header = f"{'IP':<18} {'MAC':<16} {'Age':>6} {'Type':<10} {'Interface'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(
            f"{e['ip']:<18} {e['mac']:<16} {e['age']:>6} {e['type']:<10} {e['iface']}"
        )
    print(f"\n{len(entries)} ARP entries")

    if anomalies:
        print(f"\n{'='*50}")
        print(f"ANOMALIES DETECTED: {len(anomalies)}")
        print("=" * 50)
        for a in anomalies:
            print(f"[{a['severity']}] {a['type']}: {a['detail']}")
    else:
        print("\nNo anomalies detected.")


def main():
    parser = argparse.ArgumentParser(description="ARP table anomaly detector")
    parser.add_argument("-d", "--device", required=True, help="Device hostname/IP")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", dest="key_path", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--vrf", default=None, help="VRF name (omit for global table)")
    parser.add_argument("--json", dest="as_json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if not args.password and not args.key_path:
        parser.error("Provide --password or --key")

    cmd = "show ip arp"
    if args.vrf:
        cmd = f"show ip arp vrf {args.vrf}"

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = connect(
            args.device, args.port, args.username,
            args.password, args.key_path, args.timeout,
        )
    except (paramiko.AuthenticationException, paramiko.SSHException) as exc:
        log.error("SSH error: %s", exc)
        sys.exit(1)

    try:
        raw = run_command(client, cmd)
    finally:
        client.close()

    entries = parse_arp(raw)
    if not entries:
        log.error("No ARP entries parsed — check device type or VRF name")
        sys.exit(1)

    anomalies = detect_anomalies(entries)

    if args.as_json:
        print(json.dumps({"entries": entries, "anomalies": anomalies}, indent=2))
    else:
        print_table(entries, anomalies)

    sys.exit(1 if any(a["severity"] == "HIGH" for a in anomalies) else 0)


if __name__ == "__main__":
    main()
```