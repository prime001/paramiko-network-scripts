This is the NetAutoCommitter repo itself — the paramiko script goes directly as output. Here's the complete script:

```python
"""
vlan_provisioner.py - Batch VLAN provisioning for Cisco IOS/IOS-XE switches.

Purpose:
    Create, verify, or remove VLANs on a Cisco switch via SSH. Reads VLAN
    definitions from a JSON file or inline CLI flags, verifies results with
    'show vlan brief', and optionally saves the running config.

Usage:
    python vlan_provisioner.py --host 192.168.1.1 --username admin \
        --vlans vlans.json

    python vlan_provisioner.py --host 192.168.1.1 --username admin \
        --vlan-id 100 --vlan-name SERVERS --vlan-id 200 --vlan-name GUEST

    python vlan_provisioner.py --host 192.168.1.1 --username admin \
        --vlans vlans.json --remove --no-save

Prerequisites:
    pip install paramiko
    SSH and 'ip ssh version 2' enabled on target device.

JSON file format:
    [{"id": 100, "name": "SERVERS"}, {"id": 200, "name": "GUEST"}]
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def _send(shell, command, delay=1.0):
    shell.send(command + "\n")
    time.sleep(delay)
    output = ""
    while shell.recv_ready():
        output += shell.recv(8192).decode("utf-8", errors="replace")
    return output


def connect(host, port, username, password, timeout):
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


def open_shell(client):
    shell = client.invoke_shell(width=220, height=50)
    time.sleep(1.5)
    shell.recv(8192)  # drain banner and initial prompt
    _send(shell, "terminal length 0", delay=0.5)
    return shell


def get_existing_vlans(shell):
    output = _send(shell, "show vlan brief", delay=2.0)
    vlans = {}
    for line in output.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+active", line, re.IGNORECASE)
        if m:
            vlans[int(m.group(1))] = m.group(2)
    return vlans


def provision_vlans(shell, vlans):
    _send(shell, "configure terminal", delay=0.5)
    provisioned = []
    for entry in vlans:
        vid = entry["id"]
        name = entry.get("name", f"VLAN{vid:04d}")
        log.info("  Adding VLAN %d  name=%s", vid, name)
        _send(shell, f"vlan {vid}", delay=0.3)
        _send(shell, f" name {name}", delay=0.3)
        provisioned.append(vid)
    _send(shell, "end", delay=0.8)
    return provisioned


def remove_vlans(shell, vlans):
    _send(shell, "configure terminal", delay=0.5)
    removed = []
    for entry in vlans:
        vid = entry["id"]
        log.info("  Removing VLAN %d", vid)
        _send(shell, f"no vlan {vid}", delay=0.5)
        removed.append(vid)
    _send(shell, "end", delay=0.8)
    return removed


def save_config(shell):
    log.info("Saving configuration...")
    out = _send(shell, "write memory", delay=4.0)
    if re.search(r"OK|Building configuration|success", out, re.IGNORECASE):
        log.info("Configuration saved.")
    else:
        log.warning("Unexpected save response: %s", out.strip()[-120:])


def verify_vlans(shell, expected_ids):
    existing = get_existing_vlans(shell)
    present = [v for v in expected_ids if v in existing]
    missing = [v for v in expected_ids if v not in existing]
    return present, missing


def build_vlan_list(args):
    vlans = []
    if args.vlans:
        try:
            with open(args.vlans) as fh:
                vlans = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Failed to read %s: %s", args.vlans, exc)
            sys.exit(1)
    if args.vlan_ids:
        names = args.vlan_names or []
        for i, vid in enumerate(args.vlan_ids):
            vlans.append({"id": vid, "name": names[i] if i < len(names) else f"VLAN{vid:04d}"})
    if not vlans:
        log.error("No VLANs specified. Use --vlans FILE or --vlan-id/--vlan-name.")
        sys.exit(1)
    for entry in vlans:
        if not (1 <= entry["id"] <= 4094):
            log.error("Invalid VLAN ID %d (must be 1-4094)", entry["id"])
            sys.exit(1)
    return vlans


def parse_args():
    parser = argparse.ArgumentParser(
        description="Provision or remove VLANs on a Cisco IOS/IOS-XE switch via SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP address")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--vlans", metavar="FILE", help="JSON file with VLAN definitions")
    parser.add_argument(
        "--vlan-id", dest="vlan_ids", type=int, action="append", metavar="ID",
        help="VLAN ID to provision (repeatable)",
    )
    parser.add_argument(
        "--vlan-name", dest="vlan_names", action="append", metavar="NAME",
        help="VLAN name matching position of --vlan-id",
    )
    parser.add_argument("--remove", action="store_true", help="Remove VLANs instead of adding")
    parser.add_argument("--no-save", action="store_true", help="Skip 'write memory' after changes")
    parser.add_argument("--timeout", type=int, default=15, help="SSH connection timeout (default: 15)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")
    vlans = build_vlan_list(args)

    log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        client = connect(args.host, args.port, args.username, password, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        shell = open_shell(client)
        existing = get_existing_vlans(shell)
        log.info("Existing VLANs: %s", sorted(existing.keys()))

        if args.remove:
            protected = [v["id"] for v in vlans if v["id"] in (1,)]
            if protected:
                log.error("Refusing to remove reserved VLAN(s): %s", protected)
                sys.exit(1)
            removed = remove_vlans(shell, vlans)
            log.info("Removed %d VLAN(s): %s", len(removed), removed)
        else:
            provisioned = provision_vlans(shell, vlans)
            present, missing = verify_vlans(shell, provisioned)
            log.info("Verified active: %s", present)
            if missing:
                log.warning("Not found after provisioning (may need 'vtp mode transparent'): %s", missing)

        if not args.no_save:
            save_config(shell)
    except KeyboardInterrupt:
        log.info("Interrupted by user.")
        sys.exit(130)
    finally:
        client.close()
        log.info("Disconnected from %s", args.host)
```