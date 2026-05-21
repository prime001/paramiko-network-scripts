Writing a VLAN provisioner script — distinct from the existing config_deploy scripts by targeting VLAN lifecycle management specifically (add/remove/list with pre-check).

```python
"""vlan_provisioner.py - Deploy and manage VLANs on Cisco IOS/IOS-XE switches via SSH.

Usage:
    # List VLANs currently on device
    python vlan_provisioner.py --host 192.168.1.1 --user admin --action list

    # Add VLANs from a JSON definition file
    python vlan_provisioner.py --host 192.168.1.1 --user admin --action add --vlan-file vlans.json

    # Remove one or more VLANs by ID
    python vlan_provisioner.py --host 192.168.1.1 --user admin --action remove --vlan-id 100 200

    VLAN JSON file format:
        [{"id": 100, "name": "SERVERS"}, {"id": 200, "name": "VOICE"}]

Prerequisites:
    pip install paramiko
    SSH access to target switch with privilege level 15 (or enable configured)
    Device must support 'show vlan brief' and IOS-style vlan database config mode
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
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=15):
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
    return client


def send(shell, command, delay=0.5):
    shell.send(command + "\n")
    time.sleep(delay)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.1)
    return output


def get_existing_vlans(shell):
    output = send(shell, "show vlan brief", delay=1.0)
    vlans = {}
    for line in output.splitlines():
        match = re.match(r"^(\d+)\s+(\S+)\s+active", line)
        if match:
            vlans[int(match.group(1))] = match.group(2)
    return vlans


def add_vlans(shell, vlan_list):
    existing = get_existing_vlans(shell)
    results = []

    send(shell, "configure terminal")
    for entry in vlan_list:
        vlan_id = int(entry["id"])
        vlan_name = entry.get("name", f"VLAN{vlan_id:04d}")

        if vlan_id in existing:
            log.info("VLAN %d (%s) already exists — skipped", vlan_id, vlan_name)
            results.append({"id": vlan_id, "name": vlan_name, "status": "skipped"})
            continue

        send(shell, f"vlan {vlan_id}")
        send(shell, f"name {vlan_name}")
        send(shell, "exit")
        log.info("Added VLAN %d (%s)", vlan_id, vlan_name)
        results.append({"id": vlan_id, "name": vlan_name, "status": "added"})

    send(shell, "end")
    send(shell, "write memory", delay=2.0)
    return results


def remove_vlans(shell, vlan_ids):
    existing = get_existing_vlans(shell)
    results = []

    send(shell, "configure terminal")
    for vlan_id in vlan_ids:
        vlan_id = int(vlan_id)

        if vlan_id == 1:
            log.warning("Refusing to remove VLAN 1 (native/default)")
            results.append({"id": vlan_id, "status": "refused"})
            continue

        if vlan_id not in existing:
            log.warning("VLAN %d not found — skipped", vlan_id)
            results.append({"id": vlan_id, "status": "not_found"})
            continue

        send(shell, f"no vlan {vlan_id}")
        log.info("Removed VLAN %d (%s)", vlan_id, existing[vlan_id])
        results.append({"id": vlan_id, "name": existing[vlan_id], "status": "removed"})

    send(shell, "end")
    send(shell, "write memory", delay=2.0)
    return results


def list_vlans(shell):
    vlans = get_existing_vlans(shell)
    print(f"\n{'ID':<8} {'Name':<32}")
    print("-" * 40)
    for vlan_id in sorted(vlans):
        print(f"{vlan_id:<8} {vlans[vlan_id]:<32}")
    print(f"\nTotal: {len(vlans)} VLANs\n")
    return vlans


def main():
    parser = argparse.ArgumentParser(
        description="Add, remove, or list VLANs on Cisco IOS/IOS-XE switches"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--action",
        choices=["add", "remove", "list"],
        required=True,
        help="Action to perform",
    )
    parser.add_argument(
        "--vlan-file",
        help="JSON file with VLAN definitions [{id, name}, ...] — required for 'add'",
    )
    parser.add_argument(
        "--vlan-id",
        type=int,
        nargs="+",
        metavar="ID",
        help="VLAN ID(s) to remove — required for 'remove'",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.action == "add" and not args.vlan_file:
        parser.error("--vlan-file is required when action is 'add'")
    if args.action == "remove" and not args.vlan_id:
        parser.error("--vlan-id is required when action is 'remove'")

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        client = ssh_connect(args.host, args.user, password, args.port)
        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(65535)  # drain banner/MOTD

        send(shell, "terminal length 0")

        if args.action == "list":
            list_vlans(shell)

        elif args.action == "add":
            with open(args.vlan_file) as f:
                vlan_list = json.load(f)
            results = add_vlans(shell, vlan_list)
            added = sum(1 for r in results if r["status"] == "added")
            skipped = sum(1 for r in results if r["status"] == "skipped")
            log.info("Complete: %d added, %d skipped", added, skipped)

        elif args.action == "remove":
            results = remove_vlans(shell, args.vlan_id)
            removed = sum(1 for r in results if r["status"] == "removed")
            log.info("Complete: %d removed", removed)

        client.close()

    except FileNotFoundError as exc:
        log.error("File not found: %s", exc)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        log.error("Invalid JSON in VLAN file: %s", exc)
        sys.exit(1)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
```