```python
"""
vlan_manager.py - VLAN Provisioning and Verification Tool

Purpose:
    Deploy, remove, and audit VLANs on Cisco IOS/IOS-XE switches via SSH.
    Supports single-device operations and bulk provisioning from a JSON file.

Usage:
    # Add a single VLAN
    python vlan_manager.py -H 192.168.1.1 -u admin -p secret --action add --vlan 100 --name SERVERS

    # Remove a VLAN
    python vlan_manager.py -H 192.168.1.1 -u admin -p secret --action remove --vlan 100

    # Audit VLANs (show current state, no changes)
    python vlan_manager.py -H 192.168.1.1 -u admin -p secret --action audit

    # Bulk provision from JSON file
    python vlan_manager.py -H 192.168.1.1 -u admin -p secret --action bulk --file vlans.json

    JSON file format:
        [
            {"id": 100, "name": "SERVERS"},
            {"id": 200, "name": "MGMT"},
            {"id": 300, "name": "GUEST"}
        ]

Prerequisites:
    pip install paramiko
    Target device must have SSH enabled and the user must have privilege 15.
"""

import argparse
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
log = logging.getLogger(__name__)


def open_shell(client, timeout=30):
    shell = client.invoke_shell(width=200, height=50)
    shell.settimeout(timeout)
    time.sleep(1)
    shell.recv(65535)  # drain banner/prompt
    return shell


def send_command(shell, command, wait=1.5):
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.3)
    return output


def connect(host, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    log.info("Connected to %s:%d", host, port)
    return client


def enter_enable_and_config(shell, enable_secret=None):
    prompt = send_command(shell, "", wait=0.5)
    if ">" in prompt.splitlines()[-1] if prompt.strip() else False:
        pw = enable_secret or ""
        send_command(shell, "enable", wait=0.5)
        send_command(shell, pw, wait=0.5)
    send_command(shell, "terminal length 0", wait=0.5)


def parse_vlan_table(raw):
    vlans = {}
    for line in raw.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\S+)\s+\S+", line)
        if m:
            vlan_id = int(m.group(1))
            name = m.group(2)
            vlans[vlan_id] = name
    return vlans


def audit_vlans(shell):
    log.info("Fetching VLAN table...")
    output = send_command(shell, "show vlan brief", wait=2)
    vlans = parse_vlan_table(output)
    print(f"\n{'VLAN ID':<10} {'Name':<32}")
    print("-" * 42)
    for vid in sorted(vlans):
        print(f"{vid:<10} {vlans[vid]:<32}")
    print(f"\nTotal: {len(vlans)} VLAN(s)\n")
    return vlans


def add_vlan(shell, vlan_id, vlan_name):
    log.info("Adding VLAN %d (%s)...", vlan_id, vlan_name)
    send_command(shell, "configure terminal", wait=0.5)
    send_command(shell, f"vlan {vlan_id}", wait=0.5)
    send_command(shell, f"name {vlan_name}", wait=0.5)
    send_command(shell, "exit", wait=0.5)
    output = send_command(shell, "end", wait=0.5)

    verify = send_command(shell, f"show vlan id {vlan_id}", wait=1.5)
    if str(vlan_id) in verify and vlan_name in verify:
        log.info("VLAN %d verified on device.", vlan_id)
        return True
    else:
        log.warning("VLAN %d could not be verified after add.", vlan_id)
        return False


def remove_vlan(shell, vlan_id):
    log.info("Removing VLAN %d...", vlan_id)
    send_command(shell, "configure terminal", wait=0.5)
    send_command(shell, f"no vlan {vlan_id}", wait=0.5)
    send_command(shell, "end", wait=0.5)

    verify = send_command(shell, f"show vlan id {vlan_id}", wait=1.5)
    if "not found" in verify.lower() or str(vlan_id) not in verify:
        log.info("VLAN %d successfully removed.", vlan_id)
        return True
    else:
        log.warning("VLAN %d may still be present after removal.", vlan_id)
        return False


def bulk_provision(shell, vlan_file):
    try:
        with open(vlan_file) as f:
            vlans = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log.error("Failed to load VLAN file: %s", e)
        return

    results = {"added": [], "failed": []}
    for entry in vlans:
        vid = entry.get("id")
        name = entry.get("name", f"VLAN{vid}")
        if not isinstance(vid, int) or not (1 <= vid <= 4094):
            log.warning("Skipping invalid VLAN entry: %s", entry)
            continue
        ok = add_vlan(shell, vid, name)
        (results["added"] if ok else results["failed"]).append(vid)

    print(f"\nBulk result: {len(results['added'])} added, {len(results['failed'])} failed")
    if results["failed"]:
        print(f"Failed VLANs: {results['failed']}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="VLAN provisioning and audit tool for Cisco IOS/IOS-XE"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-e", "--enable", default=None, help="Enable secret (if required)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--action",
        required=True,
        choices=["add", "remove", "audit", "bulk"],
        help="Operation to perform",
    )
    parser.add_argument("--vlan", type=int, help="VLAN ID (required for add/remove)")
    parser.add_argument("--name", default=None, help="VLAN name (used with --action add)")
    parser.add_argument("--file", help="JSON file with VLAN list (required for bulk)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.action == "add" and not args.vlan:
        log.error("--vlan is required for action 'add'")
        sys.exit(1)
    if args.action == "remove" and not args.vlan:
        log.error("--vlan is required for action 'remove'")
        sys.exit(1)
    if args.action == "bulk" and not args.file:
        log.error("--file is required for action 'bulk'")
        sys.exit(1)

    try:
        client = connect(args.host, args.port, args.username, args.password)
        shell = open_shell(client)
        enter_enable_and_config(shell, args.enable)

        if args.action == "audit":
            audit_vlans(shell)
        elif args.action == "add":
            name = args.name or f"VLAN{args.vlan}"
            success = add_vlan(shell, args.vlan, name)
            sys.exit(0 if success else 1)
        elif args.action == "remove":
            success = remove_vlan(shell, args.vlan)
            sys.exit(0 if success else 1)
        elif args.action == "bulk":
            bulk_provision(shell, args.file)

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except paramiko.SSHException as e:
        log.error("SSH error: %s", e)
        sys.exit(1)
    except OSError as e:
        log.error("Connection error: %s", e)
        sys.exit(1)
    finally:
        try:
            client.close()
            log.info("Connection closed.")
        except Exception:
            pass
```