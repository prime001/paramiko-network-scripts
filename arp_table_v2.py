arp_table_monitor.py - ARP Table Change Monitor

Purpose:
    Connects to a Cisco IOS/IOS-XE device via SSH, retrieves the current ARP
    table, and optionally compares it against a saved baseline to detect new
    hosts, removed entries, and IP/MAC binding changes. Useful for spotting
    rogue devices, ARP poisoning attempts, and unauthorized DHCP assignments.

Usage:
    # One-shot snapshot:
    python arp_table_monitor.py --host 192.168.1.1 --user admin

    # Save current table as baseline:
    python arp_table_monitor.py --host 192.168.1.1 --user admin --baseline save

    # Compare current table against saved baseline:
    python arp_table_monitor.py --host 192.168.1.1 --user admin --baseline compare

    # Use a non-default baseline file:
    python arp_table_monitor.py --host 192.168.1.1 --user admin \
        --baseline compare --baseline-file /tmp/arp_snap.json

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Tested against Cisco IOS 15.x and IOS-XE 17.x.
    'show arp' output must follow the standard Cisco columnar format.
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from getpass import getpass

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_ARP_RE = re.compile(
    r"(?P<protocol>\S+)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<age>\S+)\s+"
    r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<encap>\S+)\s+"
    r"(?P<interface>\S+)"
)


def _connect(host, port, username, password, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(client, command, settle=3):
    shell = client.invoke_shell(width=220, height=50)
    shell.settimeout(settle + 2)
    time.sleep(1)
    shell.recv(8192)  # drain banner/prompt
    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(8192)
    shell.send(command + "\n")
    time.sleep(settle)
    buf = ""
    while shell.recv_ready():
        buf += shell.recv(65535).decode("utf-8", errors="replace")
    shell.close()
    return buf


def parse_arp(raw):
    entries = {}
    for line in raw.splitlines():
        m = _ARP_RE.search(line)
        if m:
            ip = m.group("ip")
            entries[ip] = {
                "mac": m.group("mac").lower(),
                "interface": m.group("interface"),
                "protocol": m.group("protocol"),
            }
    return entries


def save_baseline(entries, path):
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count": len(entries),
        "entries": entries,
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    log.info("Baseline saved → %s  (%d entries)", path, len(entries))


def load_baseline(path):
    if not os.path.exists(path):
        log.error("Baseline file not found: %s", path)
        sys.exit(1)
    with open(path) as fh:
        data = json.load(fh)
    log.info("Baseline loaded: %s  (%d entries)", data.get("timestamp", "?"), data["count"])
    return data["entries"]


def diff_tables(old, new):
    added = {ip: new[ip] for ip in new if ip not in old}
    removed = {ip: old[ip] for ip in old if ip not in new}
    rebound = {
        ip: {"was": old[ip]["mac"], "now": new[ip]["mac"], "iface": new[ip]["interface"]}
        for ip in new
        if ip in old and new[ip]["mac"] != old[ip]["mac"]
    }
    return added, removed, rebound


def _print_table(entries, title):
    print(f"\n{title}")
    print("─" * 62)
    print(f"  {'IP Address':<18} {'MAC Address':<20} {'Interface'}")
    print("─" * 62)
    for ip in sorted(entries):
        d = entries[ip]
        print(f"  {ip:<18} {d['mac']:<20} {d['interface']}")
    print(f"\n  {len(entries)} total entries")


def _print_diff(added, removed, rebound):
    if not (added or removed or rebound):
        print("\n  [OK] No changes detected since baseline.")
        return

    if added:
        print(f"\n  [+] {len(added)} new host(s):")
        for ip in sorted(added):
            d = added[ip]
            print(f"      + {ip:<18} {d['mac']}  {d['interface']}")

    if removed:
        print(f"\n  [-] {len(removed)} removed host(s):")
        for ip in sorted(removed):
            d = removed[ip]
            print(f"      - {ip:<18} {d['mac']}  {d['interface']}")

    if rebound:
        print(f"\n  [!] {len(rebound)} MAC binding change(s)  (possible ARP spoof):")
        for ip in sorted(rebound):
            d = rebound[ip]
            print(f"      ! {ip:<18} {d['was']} → {d['now']}  ({d['iface']})")


def _build_parser():
    p = argparse.ArgumentParser(
        description="Retrieve ARP table from a Cisco device and optionally monitor for changes."
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--user", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "--baseline",
        choices=["save", "compare"],
        metavar="MODE",
        help="'save' snapshots the current table; 'compare' diffs against a saved snapshot",
    )
    p.add_argument(
        "--baseline-file",
        default="arp_baseline.json",
        help="Baseline JSON path (default: arp_baseline.json)",
    )
    p.add_argument(
        "--command",
        default="show arp",
        help="ARP command to run (default: 'show arp')",
    )
    p.add_argument("--timeout", type=int, default=10, help="SSH connect timeout in seconds")
    p.add_argument("--debug", action="store_true", help="Verbose paramiko logging")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.user}@{args.host}: ")

    try:
        log.info("Connecting to %s:%d …", args.host, args.port)
        client = _connect(args.host, args.port, args.user, password, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Running: %s", args.command)
        raw = _run(client, args.command)
    finally:
        client.close()

    current = parse_arp(raw)
    if not current:
        log.warning("No ARP entries parsed — verify command output or adjust --command")
        log.debug("Raw output:\n%s", raw)
        sys.exit(1)

    if args.baseline == "save":
        save_baseline(current, args.baseline_file)
        _print_table(current, f"ARP Baseline — {args.host}")
    elif args.baseline == "compare":
        baseline = load_baseline(args.baseline_file)
        added, removed, rebound = diff_tables(baseline, current)
        _print_table(current, f"Current ARP Table — {args.host}")
        _print_diff(added, removed, rebound)
    else:
        _print_table(current, f"ARP Table — {args.host}")