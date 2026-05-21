vlan_provisioner.py — Bulk VLAN provisioner for Cisco IOS switches

Purpose:
    Deploys VLAN configurations (create or remove) to a network device
    via SSH, with pre/post verification and optional dry-run mode.
    Idempotent: skips VLANs that already exist or are already absent.

Usage:
    python vlan_provisioner.py -d 10.0.0.1 -u admin -p secret \
        --action add --vlans 100,101,102 --names "Mgmt,Voice,Data"

    python vlan_provisioner.py -d 10.0.0.1 -u admin -p secret \
        --action remove --vlans 100,101

    python vlan_provisioner.py -d 10.0.0.1 -u admin -p secret \
        --action add --vlans 200 --dry-run

Prerequisites:
    pip install paramiko
    Device must have SSH enabled and the user must have privilege 15
    (or supply --enable-password to reach enable mode).
"""

import argparse
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=30):
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
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(1)
    shell.recv(65535)
    return shell


def send_command(shell, command, wait=1.0):
    shell.send(command + "\n")
    time.sleep(wait)
    buf = b""
    while shell.recv_ready():
        buf += shell.recv(65535)
    return buf.decode("utf-8", errors="replace")


def enter_enable(shell, enable_password=None):
    out = send_command(shell, "enable", wait=0.5)
    if "Password" in out and enable_password:
        send_command(shell, enable_password, wait=0.5)
    send_command(shell, "terminal length 0", wait=0.5)


def get_existing_vlans(shell):
    output = send_command(shell, "show vlan brief", wait=2.0)
    vlans = set()
    for line in output.splitlines():
        m = re.match(r"^(\d+)\s+", line)
        if m:
            vlans.add(int(m.group(1)))
    return vlans


def provision_vlans(shell, vlan_ids, vlan_names, dry_run=False):
    results = []
    existing = get_existing_vlans(shell)

    for i, vlan_id in enumerate(vlan_ids):
        name = vlan_names[i] if i < len(vlan_names) else None

        if vlan_id in existing:
            log.info("VLAN %d already exists — skipping", vlan_id)
            results.append((vlan_id, "skipped", "already exists"))
            continue

        if dry_run:
            label = f" name {name}" if name else ""
            log.info("[DRY RUN] Would create VLAN %d%s", vlan_id, label)
            results.append((vlan_id, "dry-run", "would create"))
            continue

        send_command(shell, "conf t", wait=0.5)
        send_command(shell, f"vlan {vlan_id}", wait=0.5)
        if name:
            send_command(shell, f"name {name}", wait=0.5)
        send_command(shell, "end", wait=0.5)

        if vlan_id in get_existing_vlans(shell):
            log.info("VLAN %d created successfully", vlan_id)
            results.append((vlan_id, "created", name or ""))
        else:
            log.error("VLAN %d creation FAILED — not found after config push", vlan_id)
            results.append((vlan_id, "failed", "not found post-config"))

    return results


def remove_vlans(shell, vlan_ids, dry_run=False):
    results = []
    existing = get_existing_vlans(shell)

    for vlan_id in vlan_ids:
        if vlan_id not in existing:
            log.info("VLAN %d not present — nothing to remove", vlan_id)
            results.append((vlan_id, "skipped", "not present"))
            continue

        if dry_run:
            log.info("[DRY RUN] Would remove VLAN %d", vlan_id)
            results.append((vlan_id, "dry-run", "would remove"))
            continue

        send_command(shell, "conf t", wait=0.5)
        send_command(shell, f"no vlan {vlan_id}", wait=0.5)
        send_command(shell, "end", wait=0.5)

        if vlan_id not in get_existing_vlans(shell):
            log.info("VLAN %d removed successfully", vlan_id)
            results.append((vlan_id, "removed", ""))
        else:
            log.error("VLAN %d removal FAILED — still present after config push", vlan_id)
            results.append((vlan_id, "failed", "still present post-config"))

    return results


def print_results(results):
    print(f"\n{'VLAN':>6}  {'Status':<12}  Detail")
    print("-" * 42)
    for vlan_id, status, detail in results:
        print(f"{vlan_id:>6}  {status:<12}  {detail}")
    print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Provision or remove VLANs on a Cisco IOS device via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--enable-password", default=None, dest="enable_password")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--action", choices=["add", "remove"], required=True,
        help="Whether to add or remove the specified VLANs",
    )
    parser.add_argument(
        "--vlans", required=True,
        help="Comma-separated VLAN IDs to act on (e.g. 100,101,102)",
    )
    parser.add_argument(
        "--names",
        help="Comma-separated VLAN names aligned to --vlans (add action only)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview what would change without applying any configuration",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        vlan_ids = [int(v.strip()) for v in args.vlans.split(",")]
    except ValueError:
        log.error("--vlans must be a comma-separated list of integers")
        sys.exit(1)

    vlan_names = [n.strip() for n in args.names.split(",")] if args.names else []

    if args.dry_run:
        log.info("DRY RUN MODE — no changes will be applied to the device")

    try:
        log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
        client = ssh_connect(args.device, args.username, args.password, args.port)
        shell = open_shell(client)
        enter_enable(shell, args.enable_password)

        if args.action == "add":
            results = provision_vlans(shell, vlan_ids, vlan_names, args.dry_run)
        else:
            results = remove_vlans(shell, vlan_ids, args.dry_run)

        client.close()
        print_results(results)

        failures = [r for r in results if r[1] == "failed"]
        sys.exit(1 if failures else 0)

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", args.device, exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Network error connecting to %s: %s", args.device, exc)
        sys.exit(1)


if __name__ == "__main__":
    main()