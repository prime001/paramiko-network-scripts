VLAN Configuration Deployer

Connects to Cisco IOS/IOS-XE switches via SSH and deploys VLAN definitions
from a JSON specification file. Idempotent: skips VLANs already present with
the correct name, creates missing VLANs, and renames those with wrong names.
Reports a per-device change summary and optionally saves the running config.

Usage:
    python vlan_deploy.py -d 192.168.1.1 -u admin -p secret -f vlans.json
    python vlan_deploy.py -d 192.168.1.1 -u admin --ask-pass -f vlans.json --dry-run

Prerequisites:
    pip install paramiko

vlans.json format:
    [{"id": 10, "name": "MGMT"}, {"id": 20, "name": "DATA"}, {"id": 100, "name": "VOICE"}]
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
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def _drain(shell: paramiko.Channel, pause: float = 0.6) -> str:
    time.sleep(pause)
    buf = ""
    while shell.recv_ready():
        buf += shell.recv(8192).decode("utf-8", errors="replace")
    return buf


def send_cmd(shell: paramiko.Channel, cmd: str, pause: float = 0.8) -> str:
    shell.send(cmd + "\n")
    return _drain(shell, pause)


def open_interactive_shell(client: paramiko.SSHClient) -> paramiko.Channel:
    shell = client.invoke_shell(width=220, height=50)
    shell.settimeout(20)
    _drain(shell, pause=1.2)
    return shell


def get_existing_vlans(shell: paramiko.Channel) -> dict:
    """Returns {vlan_id: vlan_name} parsed from 'show vlan brief'."""
    send_cmd(shell, "end")
    out = send_cmd(shell, "show vlan brief", pause=2.0)
    vlans = {}
    for line in out.splitlines():
        m = re.match(r"^(\d{1,4})\s+(\S+)\s+active", line, re.IGNORECASE)
        if m:
            vlans[int(m.group(1))] = m.group(2)
    return vlans


def deploy_vlans(shell, vlan_spec, existing, dry_run, save):
    """Apply VLAN spec; return summary dict of changes."""
    changes = {"created": [], "renamed": [], "skipped": []}

    if not dry_run:
        send_cmd(shell, "conf t")

    for entry in vlan_spec:
        vid = int(entry["id"])
        name = str(entry["name"])
        current = existing.get(vid)

        if current is None:
            log.info("  CREATE vlan %d  name=%s", vid, name)
            changes["created"].append(vid)
            if not dry_run:
                send_cmd(shell, f"vlan {vid}")
                send_cmd(shell, f"name {name}")
        elif current.upper() != name.upper():
            log.info("  RENAME vlan %d  %s -> %s", vid, current, name)
            changes["renamed"].append(vid)
            if not dry_run:
                send_cmd(shell, f"vlan {vid}")
                send_cmd(shell, f"name {name}")
        else:
            log.debug("  SKIP   vlan %d  already correct", vid)
            changes["skipped"].append(vid)

    if not dry_run:
        send_cmd(shell, "end")
        if save and (changes["created"] or changes["renamed"]):
            log.info("Saving configuration...")
            send_cmd(shell, "write memory", pause=4.0)

    return changes


def ssh_connect(host, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return client


def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy VLAN definitions to Cisco IOS/IOS-XE switches."
    )
    parser.add_argument("-d", "--device", required=True, help="Switch IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument(
        "--ask-pass", action="store_true", help="Prompt interactively for password"
    )
    parser.add_argument("-P", "--port", type=int, default=22)
    parser.add_argument(
        "-f", "--file", required=True, metavar="VLANS_JSON",
        help="JSON file containing VLAN spec",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report planned changes without applying them",
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="Skip 'write memory' after changes",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.ask_pass or args.password is None:
        args.password = getpass.getpass(
            f"Password for {args.username}@{args.device}: "
        )

    try:
        with open(args.file) as fh:
            vlan_spec = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Cannot load VLAN spec '%s': %s", args.file, exc)
        return 1

    if not isinstance(vlan_spec, list) or not all(
        isinstance(v, dict) and "id" in v and "name" in v for v in vlan_spec
    ):
        log.error('VLAN spec must be a JSON array of {"id": int, "name": str} objects.')
        return 1

    log.info("Connecting to %s:%d ...", args.device, args.port)
    try:
        client = ssh_connect(args.device, args.port, args.username, args.password)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except Exception as exc:
        log.error("SSH connection error: %s", exc)
        return 1

    try:
        shell = open_interactive_shell(client)
        send_cmd(shell, "terminal length 0")

        existing = get_existing_vlans(shell)
        log.info("Found %d active VLAN(s) on %s", len(existing), args.device)

        if args.dry_run:
            log.info("DRY RUN mode — no changes will be committed.")

        changes = deploy_vlans(
            shell, vlan_spec, existing,
            dry_run=args.dry_run,
            save=not args.no_save,
        )
    except Exception as exc:
        log.error("Deployment error: %s", exc)
        return 1
    finally:
        client.close()

    tag = "[DRY RUN] " if args.dry_run else ""
    print(f"\n{tag}Summary for {args.device}:")
    print(f"  Created : {changes['created'] if changes['created'] else 'none'}")
    print(f"  Renamed : {changes['renamed'] if changes['renamed'] else 'none'}")
    print(f"  Skipped : {len(changes['skipped'])} VLAN(s) already correct")
    return 0


if __name__ == "__main__":
    sys.exit(main())