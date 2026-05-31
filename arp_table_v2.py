```python
"""
arp_table_v3.py - Multi-device ARP aggregation and MAC conflict detection

Purpose:
    Collects ARP tables from multiple Cisco devices in parallel using paramiko,
    aggregates results into a unified view, and flags MAC address conflicts —
    the same MAC appearing on multiple IPs across the network, which may indicate
    ARP spoofing, HSRP/VRRP virtual addresses, or misconfigured hosts.

Usage:
    # Single device
    python arp_table_v3.py -H 192.168.1.1 -u admin -p secret

    # Multiple devices from inventory file (one IP/hostname per line)
    python arp_table_v3.py -i hosts.txt -u admin -p secret

    # Export as CSV or JSON
    python arp_table_v3.py -i hosts.txt -u admin -p secret --format csv -o arp_dump.csv

    # Show only entries with MAC conflicts
    python arp_table_v3.py -i hosts.txt -u admin -p secret --conflicts-only

Prerequisites:
    pip install paramiko
    SSH access with privilege level sufficient to run 'show ip arp' (Cisco IOS/IOS-XE)
"""

import argparse
import csv
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

ARP_PATTERN = re.compile(
    r"\S+\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<age>\S+)\s+"
    r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(?P<type>\S+)\s+(?P<iface>\S+)"
)


def ssh_fetch_arp(host, username, password, port, timeout):
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
        _, stdout, stderr = client.exec_command("show ip arp", timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.debug("%s stderr: %s", host, err)
        return output
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
    except (paramiko.SSHException, OSError) as exc:
        log.error("%s: connection error — %s", host, exc)
    finally:
        client.close()
    return None


def parse_arp_output(raw, source_host):
    entries = []
    for line in raw.splitlines():
        m = ARP_PATTERN.search(line)
        if m:
            entries.append({
                "source": source_host,
                "ip": m.group("ip"),
                "mac": m.group("mac"),
                "age": m.group("age"),
                "interface": m.group("iface"),
                "type": m.group("type"),
            })
    return entries


def collect(hosts, username, password, port, timeout, workers):
    all_entries = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(ssh_fetch_arp, h, username, password, port, timeout): h
            for h in hosts
        }
        for fut in as_completed(futures):
            host = futures[fut]
            raw = fut.result()
            if raw:
                entries = parse_arp_output(raw, host)
                log.info("%s: %d ARP entries collected", host, len(entries))
                all_entries.extend(entries)
            else:
                log.warning("%s: no data collected", host)
    return all_entries


def find_conflicts(entries):
    mac_to_ips = {}
    for e in entries:
        mac_to_ips.setdefault(e["mac"], set()).add(e["ip"])
    return {mac: sorted(ips) for mac, ips in mac_to_ips.items() if len(ips) > 1}


def write_output(entries, conflicts, fmt, outfile, conflicts_only):
    conflict_macs = set(conflicts)
    display = [e for e in entries if e["mac"] in conflict_macs] if conflicts_only else entries

    target = open(outfile, "w", newline="") if outfile else sys.stdout
    try:
        if fmt == "json":
            json.dump({"entries": display, "conflicts": conflicts}, target, indent=2)
            target.write("\n")
        elif fmt == "csv":
            fields = ["source", "ip", "mac", "age", "interface", "type", "conflict"]
            writer = csv.DictWriter(target, fieldnames=fields)
            writer.writeheader()
            for e in display:
                writer.writerow({**e, "conflict": e["mac"] in conflict_macs})
        else:
            hdr = f"{'SOURCE':<22} {'IP':<18} {'MAC':<18} {'AGE':<6} {'IFACE':<16} CONFLICT"
            print(hdr, file=target)
            print("-" * len(hdr), file=target)
            for e in display:
                flag = " *" if e["mac"] in conflict_macs else ""
                print(
                    f"{e['source']:<22} {e['ip']:<18} {e['mac']:<18}"
                    f" {e['age']:<6} {e['interface']:<16}{flag}",
                    file=target,
                )
            if conflicts:
                print(f"\n{len(conflicts)} MAC conflict(s) detected:", file=target)
                for mac, ips in sorted(conflicts.items()):
                    print(f"  {mac} -> {', '.join(ips)}", file=target)
    finally:
        if outfile:
            target.close()


def main():
    parser = argparse.ArgumentParser(
        description="Collect ARP tables from multiple devices and detect MAC conflicts"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-H", "--host", help="Single target device")
    src.add_argument("-i", "--inventory", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=10, help="SSH timeout in seconds")
    parser.add_argument("--workers", type=int, default=10, help="Parallel SSH threads")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table")
    parser.add_argument("-o", "--output", help="Write results to file")
    parser.add_argument("--conflicts-only", action="store_true",
                        help="Display only entries with conflicting MACs")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}: ")

    if args.host:
        hosts = [args.host]
    else:
        try:
            with open(args.inventory) as f:
                hosts = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            log.error("Cannot read inventory: %s", exc)
            sys.exit(1)

    if not hosts:
        log.error("No hosts to query")
        sys.exit(1)

    entries = collect(hosts, password=password, username=args.username,
                      port=args.port, timeout=args.timeout, workers=args.workers)
    if not entries:
        log.error("No ARP data collected from any device")
        sys.exit(1)

    conflicts = find_conflicts(entries)
    if conflicts:
        log.warning("%d MAC conflict(s) found — review output for details", len(conflicts))

    write_output(entries, conflicts, args.format, args.output, args.conflicts_only)


if __name__ == "__main__":
    main()
```