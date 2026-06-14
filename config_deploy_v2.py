```python
"""
vlan_provisioner.py - Batch VLAN provisioning for Cisco IOS/IOS-XE switches.

Purpose:
    Create or remove VLANs across one or more Cisco switches via SSH,
    then verify each change by re-querying the device. Supports dry-run
    to preview what would change without touching the device.

Usage:
    # Add VLANs to a single switch
    python vlan_provisioner.py --host 192.168.1.1 --username admin \
        --vlan-ids 100,200,300 --vlan-names "MGMT,PROD,GUEST"

    # Remove VLANs from all switches listed in a file
    python vlan_provisioner.py --hosts-file switches.txt --username admin \
        --vlan-ids 100,200 --action remove

    # Preview changes without applying them
    python vlan_provisioner.py --host 192.168.1.1 --username admin \
        --vlan-ids 100,200 --dry-run

Prerequisites:
    pip install paramiko
    SSH access with privilege level sufficient to enter configure terminal.
"""

import argparse
import getpass
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


def _drain(shell):
    buf = ""
    while shell.recv_ready():
        buf += shell.recv(65535).decode("utf-8", errors="replace")
    return buf


def send_command(shell, command, wait=1.5):
    shell.send(command + "\n")
    time.sleep(wait)
    return _drain(shell)


def connect(host, username, password, port=22, timeout=10):
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
    time.sleep(1)
    _drain(shell)
    send_command(shell, "terminal length 0", wait=0.5)
    return client, shell


def get_existing_vlans(shell):
    output = send_command(shell, "show vlan brief")
    vlans = {}
    for line in output.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)", line)
        if m:
            vlans[int(m.group(1))] = m.group(2)
    return vlans


def provision_vlans(shell, vlan_ids, vlan_names, action, dry_run):
    existing = get_existing_vlans(shell)
    results = []

    for i, vid in enumerate(vlan_ids):
        name = vlan_names[i] if i < len(vlan_names) else None

        if action == "add":
            if vid in existing:
                results.append((vid, "skipped", f"already exists as '{existing[vid]}'"))
                continue
            if dry_run:
                label = name or f"VLAN{vid:04d}"
                results.append((vid, "dry-run", f"would create '{label}'"))
                continue
            send_command(shell, "configure terminal", wait=0.5)
            send_command(shell, f"vlan {vid}", wait=0.5)
            if name:
                send_command(shell, f"name {name}", wait=0.5)
            send_command(shell, "end", wait=0.5)
            send_command(shell, "write memory", wait=3)

        elif action == "remove":
            if vid not in existing:
                results.append((vid, "skipped", "does not exist"))
                continue
            if dry_run:
                results.append((vid, "dry-run", f"would remove '{existing[vid]}'"))
                continue
            send_command(shell, "configure terminal", wait=0.5)
            send_command(shell, f"no vlan {vid}", wait=0.5)
            send_command(shell, "end", wait=0.5)
            send_command(shell, "write memory", wait=3)

        if not dry_run:
            updated = get_existing_vlans(shell)
            if action == "add":
                if vid in updated:
                    results.append((vid, "ok", f"created as '{updated[vid]}'"))
                else:
                    results.append((vid, "failed", "not present after add"))
            else:
                if vid not in updated:
                    results.append((vid, "ok", "removed and verified"))
                else:
                    results.append((vid, "failed", "still present after remove"))

    return results


def process_host(host, username, password, port, vlan_ids, vlan_names, action, dry_run):
    logger.info("Connecting to %s:%d", host, port)
    try:
        client, shell = connect(host, username, password, port)
    except Exception as exc:
        logger.error("Connection failed to %s: %s", host, exc)
        return

    try:
        results = provision_vlans(shell, vlan_ids, vlan_names, action, dry_run)
    except Exception as exc:
        logger.error("Error provisioning %s: %s", host, exc)
        results = []
    finally:
        client.close()

    for vid, status, detail in results:
        level = logging.WARNING if status in ("failed", "skipped") else logging.INFO
        logger.log(level, "%-18s VLAN %-5d %-8s %s", host, vid, status.upper(), detail)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Batch VLAN provisioning for Cisco IOS/IOS-XE switches"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single device IP or hostname")
    group.add_argument("--hosts-file", help="File with one host per line")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", help="Omit to be prompted securely")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--vlan-ids", required=True,
        help="Comma-separated VLAN IDs, e.g. 100,200,300",
    )
    parser.add_argument(
        "--vlan-names", default="",
        help="Optional comma-separated names aligned to --vlan-ids",
    )
    parser.add_argument(
        "--action", choices=["add", "remove"], default="add",
        help="add (default) or remove VLANs",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview changes without applying them",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    try:
        vlan_ids = [int(v.strip()) for v in args.vlan_ids.split(",")]
    except ValueError:
        logger.error("--vlan-ids must be comma-separated integers")
        sys.exit(1)

    vlan_names = [n.strip() for n in args.vlan_names.split(",") if n.strip()]

    if args.host:
        hosts = [args.host]
    else:
        with open(args.hosts_file) as fh:
            hosts = [
                line.strip() for line in fh
                if line.strip() and not line.startswith("#")
            ]

    if args.dry_run:
        logger.info("DRY-RUN mode — no changes will be applied")

    for host in hosts:
        process_host(
            host, args.username, password, args.port,
            vlan_ids, vlan_names, args.action, args.dry_run,
        )
```