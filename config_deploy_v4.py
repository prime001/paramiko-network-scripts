```python
"""
vlan_provisioner.py - Provision VLANs on Cisco IOS/IOS-XE switches via SSH.

Purpose:
    Reads a JSON file of VLAN definitions and deploys them to a target switch.
    Skips VLANs that already exist, verifies each new VLAN after deployment,
    and saves the running config on success.

Usage:
    python vlan_provisioner.py --host 192.168.1.1 --username admin \
        --vlans vlans.json [--port 22] [--timeout 30] [--dry-run]

Prerequisites:
    - pip install paramiko
    - SSH enabled on device (ip ssh version 2)
    - Account with privilege 15 or access to 'configure terminal'

vlans.json format:
    [
        {"id": 10, "name": "USERS"},
        {"id": 20, "name": "SERVERS"},
        {"id": 99, "name": "MGMT"}
    ]
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
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def load_vlans(path):
    """Load and validate VLAN definitions from a JSON file."""
    try:
        with open(path) as f:
            vlans = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"Cannot read VLAN file {path}: {e}") from e

    if not isinstance(vlans, list) or not vlans:
        raise ValueError("VLAN file must be a non-empty JSON array")

    validated = []
    for entry in vlans:
        vid = entry.get("id")
        name = str(entry.get("name", "")).strip()
        if not isinstance(vid, int) or not (1 <= vid <= 4094):
            raise ValueError(f"Invalid VLAN ID {vid!r} — must be integer 1-4094")
        if not name or not re.match(r"^[\w-]{1,32}$", name):
            raise ValueError(f"Invalid VLAN name {name!r} — 1-32 word chars or hyphens")
        validated.append({"id": vid, "name": name})

    return validated


def send_command(shell, command, wait=1.0):
    """Send a command to the interactive shell and return output."""
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(8192).decode("utf-8", errors="replace")
    return output


def connect(host, port, username, password, timeout):
    """Open SSH connection and return (SSHClient, shell)."""
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
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(1.5)
    shell.recv(8192)  # drain login banner
    return client, shell


def get_existing_vlans(shell):
    """Return set of VLAN IDs currently configured on the device."""
    output = send_command(shell, "show vlan brief", wait=2.0)
    ids = set()
    for line in output.splitlines():
        m = re.match(r"^\s*(\d{1,4})\s+\S", line)
        if m:
            ids.add(int(m.group(1)))
    return ids


def provision_vlans(shell, vlans, dry_run=False):
    """
    Deploy VLAN definitions to the device.

    Returns dict mapping VLAN ID -> 'added' | 'exists' | 'failed' | 'dry-run'.
    """
    existing = get_existing_vlans(shell)
    logger.info("Device has %d VLANs configured", len(existing))

    results = {}
    to_add = []

    for v in vlans:
        if v["id"] in existing:
            logger.info("VLAN %d (%s) already present — skipping", v["id"], v["name"])
            results[v["id"]] = "exists"
        else:
            to_add.append(v)

    if not to_add:
        logger.info("Nothing to provision — all requested VLANs already exist")
        return results

    if dry_run:
        for v in to_add:
            logger.info("[DRY-RUN] Would add: vlan %d  name %s", v["id"], v["name"])
            results[v["id"]] = "dry-run"
        return results

    send_command(shell, "configure terminal", wait=0.5)
    for v in to_add:
        logger.info("Configuring VLAN %d (%s)", v["id"], v["name"])
        send_command(shell, f"vlan {v['id']}", wait=0.3)
        send_command(shell, f"name {v['name']}", wait=0.3)
    send_command(shell, "end", wait=0.5)
    send_command(shell, "write memory", wait=4.0)

    post = get_existing_vlans(shell)
    for v in to_add:
        if v["id"] in post:
            logger.info("VLAN %d (%s) — confirmed", v["id"], v["name"])
            results[v["id"]] = "added"
        else:
            logger.error("VLAN %d (%s) — missing after deployment", v["id"], v["name"])
            results[v["id"]] = "failed"

    return results


def build_parser():
    p = argparse.ArgumentParser(
        description="Provision VLANs on Cisco IOS/IOS-XE switches via SSH"
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--timeout", type=int, default=30, help="Connection timeout in seconds (default: 30)"
    )
    p.add_argument(
        "--vlans", required=True, metavar="FILE",
        help='JSON file: [{"id": 10, "name": "USERS"}, ...]',
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be configured without making any changes",
    )
    return p


def main():
    args = build_parser().parse_args()

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    try:
        vlans = load_vlans(args.vlans)
    except ValueError as e:
        logger.error("%s", e)
        sys.exit(1)

    logger.info(
        "Loaded %d VLAN definition(s) from %s", len(vlans), args.vlans
    )
    logger.info("Connecting to %s:%d", args.host, args.port)

    client = None
    try:
        client, shell = connect(
            args.host, args.port, args.username, password, args.timeout
        )
        logger.info("SSH session established")

        results = provision_vlans(shell, vlans, dry_run=args.dry_run)

        added = sum(1 for s in results.values() if s == "added")
        skipped = sum(1 for s in results.values() if s == "exists")
        dry = sum(1 for s in results.values() if s == "dry-run")
        failed = sum(1 for s in results.values() if s == "failed")

        parts = [f"{added} added", f"{skipped} already present"]
        if dry:
            parts.append(f"{dry} dry-run")
        if failed:
            parts.append(f"{failed} FAILED")

        print("\nSummary: " + ", ".join(parts))
        if failed:
            sys.exit(2)

    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except paramiko.SSHException as e:
        logger.error("SSH error: %s", e)
        sys.exit(1)
    except OSError as e:
        logger.error("Connection error: %s", e)
        sys.exit(1)
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    main()
```