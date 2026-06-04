#!/usr/bin/env python3
"""
vlan_audit.py - Cross-device VLAN consistency auditor

Purpose:
    Connects to multiple network switches via SSH and audits VLAN consistency
    across the fleet. Identifies VLANs present on some switches but missing on
    others, helping catch provisioning gaps before they cause traffic black-holes.

Usage:
    python vlan_audit.py --hosts 10.0.0.1 10.0.0.2 10.0.0.3 \
        --username admin --password secret

    python vlan_audit.py --inventory switches.txt \
        --username netops --key-file ~/.ssh/id_rsa --output audit.json

Prerequisites:
    pip install paramiko

    Devices must have SSH enabled. The account needs read access to
    run 'show vlan brief' (Cisco IOS/NX-OS). Exits 0 when all VLANs are
    consistent, 2 when discrepancies are found (useful in CI pipelines).
"""

import argparse
import getpass
import json
import logging
import re
import sys
from collections import defaultdict
from typing import Dict, List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# Legacy token-ring VLANs that IOS always reports; skip them in comparisons.
_LEGACY_VLANS = {1002, 1003, 1004, 1005}


def ssh_connect(
    host: str,
    username: str,
    password: Optional[str],
    key_file: Optional[str],
    port: int,
    timeout: int,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": host,
        "username": username,
        "port": port,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return out


def parse_vlan_brief(output: str) -> Dict[int, dict]:
    """Return {vlan_id: {name, status}} from 'show vlan brief' output."""
    vlans: Dict[int, dict] = {}
    pattern = re.compile(
        r"^(\d+)\s+(\S+)\s+(active|act/unsup|suspended|unsupported)",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        vid = int(m.group(1))
        if vid in _LEGACY_VLANS:
            continue
        vlans[vid] = {"name": m.group(2), "status": m.group(3).lower()}
    return vlans


def build_audit_report(device_vlans: Dict[str, Dict[int, dict]]) -> dict:
    """Produce a consistency report comparing VLAN tables across all devices."""
    all_vlans: set = set()
    for vlans in device_vlans.values():
        all_vlans.update(vlans)

    presence: Dict[int, List[str]] = defaultdict(list)
    for vid in all_vlans:
        for host, vlans in device_vlans.items():
            if vid in vlans:
                presence[vid].append(host)

    n_devices = len(device_vlans)
    universal = sorted(v for v, hosts in presence.items() if len(hosts) == n_devices)
    partial = {v: hosts for v, hosts in presence.items() if len(hosts) < n_devices}

    per_device = {}
    for host, vlans in device_vlans.items():
        per_device[host] = {
            "vlan_count": len(vlans),
            "missing_vlans": sorted(v for v in partial if v not in vlans),
            "device_only_vlans": sorted(v for v in vlans if presence[v] == [host]),
        }

    return {
        "universal_vlans": universal,
        "inconsistent_vlans": {str(v): sorted(hosts) for v, hosts in sorted(partial.items())},
        "per_device": per_device,
    }


def load_inventory(path: str) -> List[str]:
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit VLAN consistency across multiple switches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--hosts", nargs="+", metavar="HOST")
    src.add_argument("--inventory", metavar="FILE", help="One host per line")

    p.add_argument("--username", required=True)
    creds = p.add_mutually_exclusive_group()
    creds.add_argument("--password")
    creds.add_argument("--key-file", metavar="PATH")

    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=10, metavar="SEC")
    p.add_argument("--output", metavar="FILE", help="Write JSON report here")
    p.add_argument("--verbose", action="store_true")
    return p


def main() -> None:
    args = build_parser().parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    hosts = args.hosts if args.hosts else load_inventory(args.inventory)
    if not hosts:
        log.error("No hosts to audit")
        sys.exit(1)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}: ")

    device_vlans: Dict[str, Dict[int, dict]] = {}
    failed: List[str] = []

    for host in hosts:
        log.info("Querying %s", host)
        try:
            client = ssh_connect(
                host, args.username, args.password, args.key_file,
                args.port, args.timeout,
            )
            raw = run_command(client, "show vlan brief")
            client.close()
            vlans = parse_vlan_brief(raw)
            device_vlans[host] = vlans
            log.info("%s: %d VLANs found", host, len(vlans))
        except paramiko.AuthenticationException:
            log.error("%s: authentication failed", host)
            failed.append(host)
        except (paramiko.SSHException, OSError) as exc:
            log.error("%s: %s", host, exc)
            failed.append(host)

    if not device_vlans:
        log.error("No devices responded")
        sys.exit(1)

    report = build_audit_report(device_vlans)
    report["failed_hosts"] = failed

    serialized = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(serialized)
        log.info("Report written to %s", args.output)
    else:
        print(serialized)

    n_inconsistent = len(report["inconsistent_vlans"])
    if n_inconsistent:
        log.warning("%d VLAN(s) inconsistent across fleet", n_inconsistent)
        sys.exit(2)
    log.info("All VLANs consistent across %d device(s)", len(device_vlans))


if __name__ == "__main__":
    main()