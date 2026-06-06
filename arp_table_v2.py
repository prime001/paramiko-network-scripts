```python
"""
arp_conflict_detector.py - Multi-device ARP conflict and duplicate-IP detector.

Purpose:
    Connects to multiple network devices via SSH, collects ARP tables, then
    cross-correlates entries to surface IP conflicts (same IP mapped to
    different MACs across devices) and suspicious MAC conflicts (same MAC
    claiming multiple IPs in ways that suggest spoofing or misconfiguration).

    Useful for auditing layer-2/3 boundary issues, catching ARP poisoning,
    diagnosing HSRP/VRRP misconfiguration, and verifying address uniqueness
    before subnet migrations.

Usage:
    python arp_conflict_detector.py -d 10.0.0.1 10.0.0.2 -u admin -p secret
    python arp_conflict_detector.py --device-file routers.txt -u netops --key ~/.ssh/id_rsa
    python arp_conflict_detector.py -d 10.0.0.1 -u admin --json > conflicts.json

Prerequisites:
    - Python 3.7+
    - paramiko: pip install paramiko
    - SSH access to Cisco IOS/IOS-XE/NX-OS devices
    - Devices must support 'show ip arp'
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from getpass import getpass

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Matches Cisco IOS: "Internet  192.168.1.1  5  aabb.cc00.0100  ARPA  Gi0/0"
ARP_LINE_RE = re.compile(
    r"Internet\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"\S+\s+"
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"ARPA\s+"
    r"(\S+)"
)


def normalize_mac(dotted):
    """Convert Cisco dotted hex (aabb.ccdd.eeff) to colon-separated lowercase."""
    digits = re.sub(r"[^0-9a-fA-F]", "", dotted)
    if len(digits) != 12:
        return dotted.lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)).lower()


def ssh_run(host, port, username, password, key_path, command, timeout):
    """Open an SSH session, run one command, return stdout. Returns None on error."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs = dict(
            hostname=host,
            port=port,
            username=username,
            timeout=timeout,
            look_for_keys=bool(key_path),
            allow_agent=False,
        )
        if key_path:
            kwargs["key_filename"] = key_path
        else:
            kwargs["password"] = password

        client.connect(**kwargs)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            logger.debug("%s stderr: %s", host, err)
        return output
    except paramiko.AuthenticationException:
        logger.error("Authentication failed: %s", host)
    except paramiko.SSHException as exc:
        logger.error("SSH error on %s: %s", host, exc)
    except OSError as exc:
        logger.error("Connection failed to %s: %s", host, exc)
    finally:
        client.close()
    return None


def collect_arp(host, port, username, password, key_path, timeout):
    """Return list of (ip, mac, interface) tuples from the device ARP table."""
    raw = ssh_run(host, port, username, password, key_path, "show ip arp", timeout)
    if raw is None:
        return []
    entries = []
    for line in raw.splitlines():
        m = ARP_LINE_RE.search(line)
        if m:
            entries.append((m.group(1), normalize_mac(m.group(2)), m.group(3)))
    logger.info("%s: collected %d ARP entries", host, len(entries))
    return entries


def detect_conflicts(device_arps):
    """
    Cross-correlate ARP tables from all devices.

    Returns:
        ip_conflicts  – {ip:  {mac: [device, ...]}}  same IP → different MACs
        mac_conflicts – {mac: {ip:  [device, ...]}}  same MAC → many IPs
    """
    ip_to_macs = defaultdict(lambda: defaultdict(list))
    mac_to_ips = defaultdict(lambda: defaultdict(list))

    for device, entries in device_arps.items():
        for ip, mac, _iface in entries:
            ip_to_macs[ip][mac].append(device)
            mac_to_ips[mac][ip].append(device)

    ignored_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
    ip_conflicts = {ip: dict(macs) for ip, macs in ip_to_macs.items() if len(macs) > 1}
    mac_conflicts = {
        mac: dict(ips)
        for mac, ips in mac_to_ips.items()
        if len(ips) > 1 and mac not in ignored_macs
    }
    return ip_conflicts, mac_conflicts


def report(ip_conflicts, mac_conflicts, as_json):
    if as_json:
        print(json.dumps({"ip_conflicts": ip_conflicts, "mac_conflicts": mac_conflicts}, indent=2))
        return

    if ip_conflicts:
        print("\n=== IP Conflicts (same IP mapped to multiple MACs) ===")
        for ip, macs in sorted(ip_conflicts.items()):
            print(f"  {ip}")
            for mac, devices in macs.items():
                print(f"    {mac}  [{', '.join(devices)}]")
    else:
        print("\nNo IP conflicts detected.")

    if mac_conflicts:
        print("\n=== MAC Conflicts (same MAC maps to multiple IPs) ===")
        for mac, ips in sorted(mac_conflicts.items()):
            print(f"  {mac}")
            for ip, devices in ips.items():
                print(f"    {ip}  [{', '.join(devices)}]")
    else:
        print("\nNo MAC conflicts detected.")

    print(
        f"\nSummary: {len(ip_conflicts)} IP conflict(s), "
        f"{len(mac_conflicts)} MAC conflict(s)."
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect ARP conflicts across multiple network devices."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-d", "--devices", nargs="+", metavar="HOST")
    src.add_argument("--device-file", metavar="FILE", help="One device per line")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", metavar="PATH", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.devices:
        devices = args.devices
    else:
        try:
            with open(args.device_file) as fh:
                devices = [
                    ln.strip()
                    for ln in fh
                    if ln.strip() and not ln.startswith("#")
                ]
        except OSError as exc:
            logger.error("Cannot read device file: %s", exc)
            sys.exit(1)

    password = args.password
    if not password and not args.key:
        password = getpass(f"SSH password for {args.username}: ")

    device_arps = {}
    for host in devices:
        entries = collect_arp(
            host, args.port, args.username, password, args.key, args.timeout
        )
        if entries:
            device_arps[host] = entries

    if not device_arps:
        logger.error("No ARP data collected from any device.")
        sys.exit(1)

    ip_conflicts, mac_conflicts = detect_conflicts(device_arps)
    report(ip_conflicts, mac_conflicts, args.as_json)
    sys.exit(0 if not ip_conflicts and not mac_conflicts else 1)


if __name__ == "__main__":
    main()
```