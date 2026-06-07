#!/usr/bin/env python3
"""
vlan_provisioner.py — Bulk VLAN provisioning for Cisco IOS/IOS-XE switches via Paramiko.

Purpose:
    Deploy and verify VLANs on Cisco IOS/IOS-XE switches. Reads VLAN definitions
    from a JSON file or inline CLI arguments, pushes them via SSH, and confirms
    each VLAN appears in 'show vlan brief' after deployment.

Usage:
    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret --vlan-file vlans.json
    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret --vlans 10:Sales 20:Eng
    python vlan_provisioner.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa --vlans 10:Sales --dry-run

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device; user requires privilege 15.

JSON file format:
    [{"id": 10, "name": "Sales"}, {"id": 20, "name": "Engineering"}]
"""

import argparse
import json
import logging
import re
import sys
import time
from getpass import getpass

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, port, username, password=None, key_file=None, timeout=15):
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
    if key_file:
        kwargs["key_filename"] = key_file
        kwargs["look_for_keys"] = True
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def send_commands(shell, commands, delay=0.4, settle=2.0):
    for cmd in commands:
        shell.send(cmd + "\n")
        time.sleep(delay)
    time.sleep(settle)
    buf = ""
    while shell.recv_ready():
        buf += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.1)
    return buf


def existing_vlan_ids(shell):
    raw = send_commands(shell, ["show vlan brief"], settle=1.5)
    ids = set()
    for line in raw.splitlines():
        m = re.match(r"^\s*(\d+)\s+\S+", line)
        if m:
            ids.add(int(m.group(1)))
    return ids


def provision_vlans(shell, vlans, dry_run=False):
    commands = ["configure terminal"]
    for vlan in vlans:
        commands.append(f"vlan {vlan['id']}")
        if vlan.get("name"):
            commands.append(f" name {vlan['name']}")
    commands.extend(["end", "write memory"])

    if dry_run:
        log.info("[dry-run] Would send:\n  %s", "\n  ".join(commands))
        return [
            {"vlan_id": v["id"], "name": v.get("name", ""), "status": "dry-run"}
            for v in vlans
        ]

    send_commands(shell, commands, settle=4.0)
    present = existing_vlan_ids(shell)

    results = []
    for vlan in vlans:
        vid = vlan["id"]
        status = "ok" if vid in present else "FAILED"
        log.info("VLAN %-5d %-24s %s", vid, vlan.get("name", ""), status)
        results.append({"vlan_id": vid, "name": vlan.get("name", ""), "status": status})
    return results


def parse_inline_vlans(tokens):
    vlans = []
    for token in tokens:
        parts = token.split(":", 1)
        try:
            vid = int(parts[0])
        except ValueError:
            log.error("Invalid VLAN id %r — expected integer", parts[0])
            sys.exit(1)
        name = parts[1] if len(parts) > 1 else f"VLAN{vid}"
        vlans.append({"id": vid, "name": name})
    return vlans


def build_parser():
    p = argparse.ArgumentParser(
        description="Provision VLANs on a Cisco IOS/IOS-XE switch via SSH.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-P", "--port", type=int, default=22, help="SSH port (default 22)")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("--key", dest="key_file", default=None, help="SSH private key path")
    p.add_argument(
        "--vlans",
        nargs="+",
        metavar="ID[:NAME]",
        help="Inline VLAN list, e.g. 10:Sales 20:Engineering",
    )
    p.add_argument("--vlan-file", metavar="FILE", help="JSON file with VLAN definitions")
    p.add_argument("--dry-run", action="store_true", help="Print commands without applying")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if not args.vlans and not args.vlan_file:
        log.error("Provide --vlans or --vlan-file")
        sys.exit(1)

    vlans = []
    if args.vlan_file:
        with open(args.vlan_file) as fh:
            vlans.extend(json.load(fh))
    if args.vlans:
        vlans.extend(parse_inline_vlans(args.vlans))

    password = args.password
    if not password and not args.key_file:
        password = getpass(f"Password for {args.username}@{args.host}: ")

    log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        client = ssh_connect(
            host=args.host,
            port=args.port,
            username=args.username,
            password=password,
            key_file=args.key_file,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed")
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(1.0)
        shell.recv(65535)
        send_commands(shell, ["terminal length 0"], settle=0.5)

        results = provision_vlans(shell, vlans, dry_run=args.dry_run)
    finally:
        client.close()

    failed = [r for r in results if r["status"] == "FAILED"]
    if failed:
        log.warning(
            "%d VLAN(s) failed verification: %s",
            len(failed),
            [r["vlan_id"] for r in failed],
        )
        sys.exit(2)

    if not args.dry_run:
        log.info("Done. %d VLAN(s) provisioned successfully.", len(results))


if __name__ == "__main__":
    main()