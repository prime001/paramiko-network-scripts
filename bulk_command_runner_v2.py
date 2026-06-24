```
"""
vlan_audit.py - VLAN Consistency Auditor

Purpose:
    SSH to multiple Cisco IOS/IOS-XE switches and compare their VLAN databases.
    Identifies VLANs present on some switches but absent on others, and flags
    VLAN name conflicts — common symptoms of VLAN drift after incremental changes.

Usage:
    python vlan_audit.py --hosts 10.0.0.1 10.0.0.2 10.0.0.3 --username admin
    python vlan_audit.py --hosts-file switches.txt --username netops --output report.json
    python vlan_audit.py --hosts 10.0.0.1 10.0.0.2 --username admin --password secret

Prerequisites:
    pip install paramiko
    SSH access with privilege level sufficient for 'show vlan brief'
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x
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
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Cisco reserves these for legacy Token Ring / FDDI bridging; exclude from audit
RESERVED_VLANS = {1002, 1003, 1004, 1005}


def connect(host, username, password, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        logger.debug("stderr: %s", err)
    return output


def parse_vlan_brief(output):
    """
    Parse 'show vlan brief' into {vlan_id: {'name': str, 'status': str, 'ports': list}}.
    IOS wraps long port lists onto continuation lines starting with 10+ spaces.
    """
    vlans = {}
    current_vlan = None

    vlan_re = re.compile(
        r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|act/lshut|suspended|unsupported)\s*(.*)?$"
    )
    continuation_re = re.compile(r"^\s{10,}(.+)$")

    for line in output.splitlines():
        m = vlan_re.match(line)
        if m:
            vlan_id = int(m.group(1))
            current_vlan = vlan_id
            raw_ports = m.group(4).strip()
            ports = [p.strip() for p in raw_ports.split(",") if p.strip()] if raw_ports else []
            vlans[vlan_id] = {"name": m.group(2), "status": m.group(3), "ports": ports}
        elif current_vlan is not None:
            cm = continuation_re.match(line)
            if cm:
                vlans[current_vlan]["ports"].extend(
                    p.strip() for p in cm.group(1).split(",") if p.strip()
                )
            else:
                current_vlan = None

    return vlans


def collect_from_host(host, username, password, port, timeout):
    try:
        client = connect(host, username, password, port=port, timeout=timeout)
    except paramiko.AuthenticationException:
        logger.error("%s: authentication failed", host)
        return host, None, "auth_failed"
    except Exception as exc:
        logger.error("%s: connection failed — %s", host, exc)
        return host, None, str(exc)

    try:
        raw = run_command(client, "show vlan brief")
        vlans = parse_vlan_brief(raw)
        logger.info("%s: collected %d VLANs", host, len(vlans))
        return host, vlans, None
    except Exception as exc:
        logger.error("%s: command failed — %s", host, exc)
        return host, None, str(exc)
    finally:
        client.close()


def audit(results):
    successful = {h: d for h, d, _ in results if d is not None}
    if len(successful) < 2:
        return {"all_vlans": [], "missing": {}, "name_conflicts": {}, "switch_count": len(successful)}

    all_vlans = set()
    for vlans in successful.values():
        all_vlans.update(vlans.keys())
    all_vlans -= RESERVED_VLANS

    missing = defaultdict(list)
    for vlan_id in sorted(all_vlans):
        for host, vlans in successful.items():
            if vlan_id not in vlans:
                missing[vlan_id].append(host)

    name_conflicts = {}
    for vlan_id in sorted(all_vlans):
        names = {h: d[vlan_id]["name"] for h, d in successful.items() if vlan_id in d}
        if len(set(names.values())) > 1:
            name_conflicts[vlan_id] = names

    return {
        "all_vlans": sorted(all_vlans),
        "missing": dict(missing),
        "name_conflicts": name_conflicts,
        "switch_count": len(successful),
        "per_switch_vlans": {h: sorted(d.keys()) for h, d in successful.items()},
    }


def print_report(results, report):
    print("\n=== VLAN Consistency Audit Report ===\n")
    print("Collection:")
    for host, vlans, error in results:
        status = f"{len(vlans)} VLANs" if vlans is not None else f"FAILED ({error})"
        print(f"  {host:<20} {status}")

    print(f"\nUnique VLANs across {report['switch_count']} switches: {len(report['all_vlans'])}")

    if report["missing"]:
        print(f"\n[!] VLAN gaps — {len(report['missing'])} VLAN(s) missing on at least one switch:")
        for vlan_id in sorted(report["missing"]):
            absent = ", ".join(report["missing"][vlan_id])
            print(f"  VLAN {vlan_id:4d}  missing on: {absent}")
    else:
        print("\n[OK] No missing VLANs — all switches have the same VLAN IDs.")

    if report["name_conflicts"]:
        print(f"\n[!] Name conflicts — {len(report['name_conflicts'])} VLAN(s) have mismatched names:")
        for vlan_id in sorted(report["name_conflicts"]):
            print(f"  VLAN {vlan_id}:")
            for host, name in report["name_conflicts"][vlan_id].items():
                print(f"    {host}: '{name}'")
    else:
        print("\n[OK] No VLAN name conflicts detected.")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Audit VLAN database consistency across Cisco switches"
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("--hosts", nargs="+", metavar="IP")
    host_group.add_argument("--hosts-file", metavar="FILE", help="One host per line, # for comments")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", help="Prompted if omitted")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=10, metavar="SEC")
    parser.add_argument("--output", metavar="FILE", help="Write JSON report to file")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.hosts_file:
        try:
            with open(args.hosts_file) as f:
                hosts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except OSError as exc:
            logger.error("Cannot read hosts file: %s", exc)
            sys.exit(1)
    else:
        hosts = args.hosts

    if len(hosts) < 2:
        logger.error("Provide at least two hosts for a meaningful consistency check")
        sys.exit(1)

    password = args.password or getpass.getpass(f"SSH password for {args.username}: ")

    logger.info("Auditing %d switches", len(hosts))
    results = [collect_from_host(h, args.username, password, args.port, args.timeout) for h in hosts]

    report = audit(results)
    print_report(results, report)

    if args.output:
        payload = {
            "hosts": [{"host": h, "vlans": d, "error": e} for h, d, e in results],
            "audit": report,
        }
        try:
            with open(args.output, "w") as f:
                json.dump(payload, f, indent=2)
            logger.info("JSON report written to %s", args.output)
        except OSError as exc:
            logger.error("Cannot write output: %s", exc)
            sys.exit(1)

    issues = len(report["missing"]) + len(report["name_conflicts"])
    sys.exit(0 if issues == 0 else 1)


if __name__ == "__main__":
    main()
```