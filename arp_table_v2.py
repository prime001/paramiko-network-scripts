```python
"""
arp_table_v3.py - ARP Table Collector with Anomaly Detection

Retrieves ARP tables from Cisco IOS/IOS-XE devices via SSH and analyzes
entries for security anomalies: duplicate IP-to-MAC mappings (possible ARP
spoofing) and gratuitous ARP conflicts.

Usage:
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret
    python arp_table_v3.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa --json
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret --vrf MGMT

Prerequisites:
    pip install paramiko
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

ARP_PATTERN = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"   # IP address
    r"[\d\-]+\s+"                       # age
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"  # MAC (Cisco dotted)
    r"\w+\s+"                           # type (ARPA)
    r"(\S+)",                           # interface
    re.IGNORECASE,
)


def connect(host, port, username, password=None, key_path=None, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key-file")
    client.connect(**connect_kwargs)
    return client


def run_command(client, command, recv_size=65535, timeout=20):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.warning("Device stderr: %s", err)
    return output


def fetch_arp_table(client, vrf=None):
    cmd = "show ip arp"
    if vrf:
        cmd = f"show ip arp vrf {vrf}"
    log.info("Running: %s", cmd)
    return run_command(client, cmd)


def parse_arp_output(raw):
    entries = []
    for line in raw.splitlines():
        m = ARP_PATTERN.search(line)
        if not m:
            continue
        ip, mac_cisco, iface = m.group(1), m.group(2), m.group(3)
        mac_std = mac_cisco.replace(".", "").upper()
        mac_std = ":".join(mac_std[i:i+2] for i in range(0, 12, 2))
        entries.append({"ip": ip, "mac": mac_std, "interface": iface})
    return entries


def detect_anomalies(entries):
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)
    for e in entries:
        ip_to_macs[e["ip"]].add(e["mac"])
        mac_to_ips[e["mac"]].add(e["ip"])

    anomalies = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            anomalies.append({
                "type": "duplicate_ip",
                "detail": f"IP {ip} maps to multiple MACs: {sorted(macs)}",
            })
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            anomalies.append({
                "type": "duplicate_mac",
                "detail": f"MAC {mac} maps to multiple IPs: {sorted(ips)}",
            })
    return anomalies


def print_table(entries, anomalies):
    col = "{:<18} {:<20} {}"
    print(col.format("IP Address", "MAC Address", "Interface"))
    print("-" * 55)
    for e in sorted(entries, key=lambda x: x["ip"]):
        print(col.format(e["ip"], e["mac"], e["interface"]))
    print(f"\n{len(entries)} entries total")
    if anomalies:
        print(f"\n[!] {len(anomalies)} anomaly(ies) detected:")
        for a in anomalies:
            print(f"  [{a['type']}] {a['detail']}")
    else:
        print("\n[+] No ARP anomalies detected")


def main():
    parser = argparse.ArgumentParser(
        description="ARP table collector with anomaly detection"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP/hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("-k", "--key-file", dest="key_file", default=None,
                        help="SSH private key path")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--vrf", default=None, help="VRF name")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Output JSON instead of table")
    parser.add_argument("--anomalies-only", action="store_true",
                        help="Exit 1 if anomalies found (useful in scripts)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    try:
        client = connect(
            host=args.device,
            port=args.port,
            username=args.username,
            password=args.password,
            key_path=args.key_file,
        )
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        raw = fetch_arp_table(client, vrf=args.vrf)
        entries = parse_arp_output(raw)
        if not entries:
            log.warning("No ARP entries parsed — check device output format")
        anomalies = detect_anomalies(entries)

        if args.as_json:
            print(json.dumps({"entries": entries, "anomalies": anomalies}, indent=2))
        else:
            print_table(entries, anomalies)

        if args.anomalies_only and anomalies:
            sys.exit(1)

    finally:
        client.close()


if __name__ == "__main__":
    main()
```