vlan_provisioner.py — Deploy VLAN configurations to Cisco IOS switches via paramiko.

Purpose:
    Provisions one or more VLANs (create, name, assign access ports) on a target
    switch. Reads VLAN definitions from a JSON file and applies them idempotently —
    skips VLANs that already exist with a matching name.

Usage:
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret vlans.json
    python vlan_provisioner.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa vlans.json --dry-run

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.

VLAN definition file (JSON array):
    [
        {"id": 10, "name": "SERVERS", "ports": ["GigabitEthernet0/1"]},
        {"id": 20, "name": "MGMT",    "ports": []}
    ]
"""

import argparse
import json
import logging
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def _send(shell, cmd, delay=1.0):
    shell.send(cmd + "\n")
    time.sleep(delay)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode("utf-8", errors="replace")
    return output


def connect(host, port, username, password=None, key_path=None, timeout=15):
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
    if key_path:
        kwargs["key_filename"] = key_path
        kwargs["look_for_keys"] = True
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Either --password or --key must be supplied")
    client.connect(**kwargs)
    return client


def get_existing_vlans(shell):
    output = _send(shell, "show vlan brief", delay=1.5)
    existing = {}
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            vlan_id = int(parts[0])
            existing[vlan_id] = parts[1] if len(parts) > 1 else ""
    return existing


def provision_vlans(shell, vlans, existing, dry_run=False):
    prefix = "[DRY RUN] " if dry_run else ""
    results = {"created": [], "skipped": [], "ports": [], "errors": []}

    for vlan in vlans:
        vid = vlan["id"]
        name = vlan.get("name", f"VLAN{vid}")
        ports = vlan.get("ports", [])

        if vid in existing and existing[vid].upper() == name.upper():
            log.info("VLAN %d (%s) already present — skipping", vid, name)
            results["skipped"].append(vid)
            continue

        log.info("%sCreating VLAN %d name %s", prefix, vid, name)
        if not dry_run:
            _send(shell, "conf t")
            _send(shell, f"vlan {vid}")
            _send(shell, f"name {name}")
            _send(shell, "exit")

        results["created"].append(vid)

        for port in ports:
            log.info("%sAssigning %s → VLAN %d (access)", prefix, port, vid)
            if not dry_run:
                out = _send(shell, f"interface {port}")
                if "Invalid" in out or out.strip().startswith("%"):
                    msg = f"{port}: {out.strip()}"
                    log.warning("Interface error: %s", msg)
                    results["errors"].append(msg)
                    _send(shell, "exit")
                    continue
                _send(shell, "switchport mode access")
                _send(shell, f"switchport access vlan {vid}")
                _send(shell, "exit")
            results["ports"].append(f"{port}→VLAN{vid}")

    if not dry_run and (results["created"] or results["ports"]):
        _send(shell, "end")
        _send(shell, "write memory", delay=3.0)
        log.info("Configuration saved to NVRAM")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Provision VLANs on a Cisco IOS switch"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_path", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show planned changes without applying them",
    )
    parser.add_argument("vlan_file", help="JSON file with VLAN definitions")
    args = parser.parse_args()

    try:
        with open(args.vlan_file) as f:
            vlans = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log.error("Failed to read VLAN file: %s", e)
        sys.exit(1)

    if not isinstance(vlans, list) or not vlans:
        log.error("VLAN file must be a non-empty JSON array")
        sys.exit(1)

    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = connect(
            args.device, args.port, args.username,
            password=args.password, key_path=args.key_path,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as e:
        log.error("Connection error: %s", e)
        sys.exit(1)

    try:
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(1)
        shell.recv(4096)  # discard login banner

        _send(shell, "terminal length 0")
        existing = get_existing_vlans(shell)
        log.info("Device has %d existing VLANs", len(existing))

        results = provision_vlans(shell, vlans, existing, dry_run=args.dry_run)

        print("\n--- Summary ---")
        print(f"  Created : {results['created'] or 'none'}")
        print(f"  Skipped : {results['skipped'] or 'none'}")
        print(f"  Ports   : {results['ports'] or 'none'}")
        if results["errors"]:
            print(f"  Errors  : {results['errors']}")
            sys.exit(2)
    finally:
        client.close()


if __name__ == "__main__":
    main()