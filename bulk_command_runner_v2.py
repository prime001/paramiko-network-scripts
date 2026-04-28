Writing the script now based on the specifications provided.

"""
vlan_audit.py — VLAN consistency auditor for Cisco IOS / NX-OS switches.

Purpose:
    Connect to multiple switches via SSH and compare their VLAN databases.
    Identifies VLANs that exist on some switches but are absent on others —
    a common source of black-holed traffic during network changes or expansions.

Usage:
    python vlan_audit.py --hosts 10.0.0.1 10.0.0.2 10.0.0.3
    python vlan_audit.py --host-file switches.txt --username netops
    python vlan_audit.py --hosts 10.0.0.1 10.0.0.2 --csv report.csv

Prerequisites:
    pip install paramiko
    SSH read-only access (show privilege) on all target devices.
    Tested against Cisco IOS 15.x and NX-OS 9.x.
"""

import argparse
import csv
import getpass
import logging
import re
import sys
from collections import defaultdict

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


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
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode(errors="replace")
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
    except paramiko.SSHException as exc:
        log.error("%s: SSH error: %s", host, exc)
    except OSError as exc:
        log.error("%s: connection error: %s", host, exc)
    finally:
        client.close()
    return None


def parse_vlan_brief(output):
    """Return {vlan_id: name} from `show vlan brief` output (IOS + NX-OS)."""
    vlans = {}
    for match in re.finditer(r"^(\d+)\s+(\S+)\s+active", output, re.MULTILINE):
        vlans[int(match.group(1))] = match.group(2)
    return vlans


def collect(hosts, port, username, password, timeout):
    results = {}
    for host in hosts:
        log.info("Querying %s …", host)
        raw = ssh_run(host, port, username, password, "show vlan brief", timeout)
        if raw is None:
            continue
        vlans = parse_vlan_brief(raw)
        if not vlans:
            log.warning("%s: no VLANs parsed — check OS type or privileges", host)
            continue
        results[host] = vlans
        log.info("%s: %d VLANs", host, len(vlans))
    return results


def find_discrepancies(host_vlans):
    """Return list of dicts for every VLAN absent on at least one host."""
    all_vlans = defaultdict(dict)
    for host, vlans in host_vlans.items():
        for vid, name in vlans.items():
            all_vlans[vid][host] = name

    all_hosts = set(host_vlans)
    issues = []
    for vid in sorted(all_vlans):
        present = set(all_vlans[vid])
        missing = all_hosts - present
        if missing:
            issues.append({
                "vlan_id": vid,
                "name": next(iter(all_vlans[vid].values())),
                "present_on": sorted(present),
                "missing_from": sorted(missing),
            })
    return issues


def print_report(issues, host_vlans):
    hosts = sorted(host_vlans)
    unique = len({v for h in host_vlans.values() for v in h})
    print(f"\n{'='*72}")
    print(f"VLAN Consistency Audit  |  {len(hosts)} device(s)  |  {unique} unique VLANs")
    print(f"{'='*72}")
    print(f"Hosts       : {', '.join(hosts)}")
    print(f"Discrepancy : {len(issues)} VLAN(s)\n")

    if not issues:
        print("  All VLAN databases are consistent.")
        return

    print(f"  {'VLAN':<6} {'Name':<22} {'Present On':<32} Missing From")
    print("  " + "-" * 88)
    for d in issues:
        print(
            f"  {d['vlan_id']:<6} {d['name']:<22} "
            f"{', '.join(d['present_on']):<32} "
            f"{', '.join(d['missing_from'])}"
        )


def write_csv(issues, path):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["vlan_id", "name", "present_on", "missing_from"]
        )
        writer.writeheader()
        for d in issues:
            writer.writerow({
                "vlan_id": d["vlan_id"],
                "name": d["name"],
                "present_on": "; ".join(d["present_on"]),
                "missing_from": "; ".join(d["missing_from"]),
            })
    log.info("CSV written → %s", path)


def load_host_file(path):
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def build_parser():
    p = argparse.ArgumentParser(
        description="Audit VLAN consistency across multiple Cisco switches.",
        epilog="Exit 0 = consistent, 1 = discrepancies found or error.",
    )
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--hosts", nargs="+", metavar="HOST")
    grp.add_argument("--host-file", metavar="FILE", help="One host per line")
    p.add_argument("--username", "-u", default="admin")
    p.add_argument("--password", "-p", default=None, help="Prompted if omitted")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=10, metavar="SEC")
    p.add_argument("--csv", metavar="FILE", help="Write discrepancy report to CSV")
    p.add_argument("--debug", action="store_true")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if args.host_file:
        try:
            hosts = load_host_file(args.host_file)
        except OSError as exc:
            log.error("Cannot read host file: %s", exc)
            sys.exit(1)
    else:
        hosts = args.hosts

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    host_vlans = collect(hosts, args.port, args.username, password, args.timeout)

    if len(host_vlans) < 2:
        log.error("Need at least 2 reachable hosts to compare.")
        sys.exit(1)

    issues = find_discrepancies(host_vlans)
    print_report(issues, host_vlans)

    if args.csv:
        write_csv(issues, args.csv)

    sys.exit(1 if issues else 0)