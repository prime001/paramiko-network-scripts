vlan_provisioner.py - Deploy and verify VLAN configurations on Cisco IOS switches via SSH.

Purpose:
    Reads a VLAN definition file (JSON) and provisions VLANs on a target switch,
    including optional access-port assignments. Verifies each VLAN exists after
    deployment and reports success/failure per VLAN.

Usage:
    python vlan_provisioner.py --host 192.168.1.1 --username admin \
        --vlan-file vlans.json [--dry-run] [--port 22] [--timeout 30]

    VLAN JSON format:
        [
            {"id": 10, "name": "MGMT", "ports": ["GigabitEthernet0/1"]},
            {"id": 20, "name": "USERS"},
            {"id": 30, "name": "SERVERS", "ports": ["GigabitEthernet0/2", "GigabitEthernet0/3"]}
        ]

Prerequisites:
    - pip install paramiko
    - SSH access enabled on target device
    - Account with privilege 15 (or access to 'configure terminal')
    - Cisco IOS or IOS-XE device
"""

import argparse
import getpass
import json
import logging
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def connect(host, username, password, port=22, timeout=30):
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


def send_command(shell, command, delay=1.0):
    shell.send(command + "\n")
    time.sleep(delay)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
    return output


def get_existing_vlans(shell):
    output = send_command(shell, "show vlan brief", delay=1.5)
    vlans = set()
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            vlans.add(int(parts[0]))
    return vlans


def build_vlan_commands(vlan):
    vid = vlan["id"]
    name = vlan.get("name", f"VLAN{vid}")
    commands = [f"vlan {vid}", f"name {name}", "exit"]
    for port in vlan.get("ports", []):
        commands += [
            f"interface {port}",
            "switchport mode access",
            f"switchport access vlan {vid}",
            "no shutdown",
            "exit",
        ]
    return commands


def provision_vlans(shell, vlans, dry_run=False):
    results = []
    existing = get_existing_vlans(shell)
    log.info("Found %d existing VLANs on device", len(existing))

    if not dry_run:
        send_command(shell, "configure terminal", delay=0.5)

    for vlan in vlans:
        vid = vlan["id"]
        name = vlan.get("name", f"VLAN{vid}")
        port_count = len(vlan.get("ports", []))
        commands = build_vlan_commands(vlan)

        if dry_run:
            log.info("[DRY-RUN] VLAN %d (%s) — %d port(s):", vid, name, port_count)
            for cmd in commands:
                log.info("  %s", cmd)
            results.append({"vlan_id": vid, "name": name, "status": "dry-run"})
            continue

        action = "updating" if vid in existing else "creating"
        log.info("%s VLAN %d (%s) with %d port(s)", action, vid, name, port_count)

        for cmd in commands:
            send_command(shell, cmd, delay=0.3)

        results.append({"vlan_id": vid, "name": name, "status": "deployed"})

    if not dry_run:
        send_command(shell, "end", delay=0.5)
        send_command(shell, "write memory", delay=3.0)
        log.info("Configuration saved to NVRAM")

    return results


def verify_vlans(shell, vlans):
    present = get_existing_vlans(shell)
    failed = []
    for vlan in vlans:
        vid = vlan["id"]
        if vid in present:
            log.info("Verify VLAN %d: OK", vid)
        else:
            log.error("Verify VLAN %d: MISSING", vid)
            failed.append(vid)
    return failed


def parse_args():
    parser = argparse.ArgumentParser(
        description="Provision VLANs on a Cisco IOS switch via SSH"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--vlan-file", required=True, help="JSON file with VLAN definitions")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without sending them to the device",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    try:
        with open(args.vlan_file) as f:
            vlans = json.load(f)
    except OSError as e:
        log.error("Cannot read VLAN file: %s", e)
        sys.exit(1)
    except json.JSONDecodeError as e:
        log.error("Invalid JSON in VLAN file: %s", e)
        sys.exit(1)

    if not vlans:
        log.error("VLAN file contains no entries")
        sys.exit(1)

    for entry in vlans:
        if "id" not in entry or not isinstance(entry["id"], int):
            log.error("Each VLAN entry must have an integer 'id' field")
            sys.exit(1)

    log.info("Loaded %d VLAN definition(s) from %s", len(vlans), args.vlan_file)

    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        client = connect(args.host, args.username, password, args.port, args.timeout)
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(1)
        shell.recv(65535)  # drain login banner

        send_command(shell, "terminal length 0", delay=0.5)

        provision_vlans(shell, vlans, dry_run=args.dry_run)

        if not args.dry_run:
            failed = verify_vlans(shell, vlans)
            if failed:
                log.error("%d VLAN(s) missing after deployment: %s", len(failed), failed)
                client.close()
                sys.exit(2)
            log.info("All %d VLAN(s) verified successfully", len(vlans))

        client.close()
        log.info("Done")

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except paramiko.SSHException as e:
        log.error("SSH error connecting to %s: %s", args.host, e)
        sys.exit(1)
    except OSError as e:
        log.error("Network error connecting to %s: %s", args.host, e)
        sys.exit(1)