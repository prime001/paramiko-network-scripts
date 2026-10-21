Writing a VLAN provisioner script — config-deploy in nature but clearly distinct from the existing config_deploy.py scripts.

```python
"""
vlan_provisioner.py — Push VLAN configurations to Cisco IOS switches via SSH.

Purpose:
    Create, rename, or remove VLANs on one or more Cisco IOS/IOS-XE switches.
    Verifies each change by reading back 'show vlan brief' after commit.

Usage:
    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret \\
        --vlan 100 --name SERVERS --action add

    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret \\
        --vlan 100 --action remove

    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret \\
        --vlan-file vlans.csv          # CSV: vlan_id,name,action

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Account needs privilege level 15 (enable not required when priv 15 at login).
"""

import argparse
import csv
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


def _send(chan, cmd, wait=1.5):
    chan.send(cmd + "\n")
    time.sleep(wait)
    out = ""
    while chan.recv_ready():
        out += chan.recv(4096).decode("utf-8", errors="replace")
    return out


def open_shell(host, username, password, port=22, timeout=15):
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
    chan = client.invoke_shell(width=220, height=50)
    time.sleep(1.0)
    chan.recv(8192)  # drain banner/prompt
    _send(chan, "terminal length 0", wait=0.5)
    return client, chan


def vlan_exists(chan, vlan_id):
    out = _send(chan, f"show vlan id {vlan_id}", wait=1.0)
    return "active" in out.lower() or str(vlan_id) in out


def provision_vlan(chan, vlan_id, name=None, action="add"):
    if action == "remove":
        log.info("Removing VLAN %s", vlan_id)
        _send(chan, "configure terminal", wait=0.5)
        _send(chan, f"no vlan {vlan_id}", wait=0.5)
        _send(chan, "end", wait=0.5)
        _send(chan, "write memory", wait=3.0)
        if vlan_exists(chan, vlan_id):
            log.error("VLAN %s still present after removal attempt", vlan_id)
            return False
        log.info("VLAN %s removed successfully", vlan_id)
        return True

    # add or rename
    exists_before = vlan_exists(chan, vlan_id)
    verb = "Updating" if exists_before else "Creating"
    log.info("%s VLAN %s%s", verb, vlan_id, f" ({name})" if name else "")
    _send(chan, "configure terminal", wait=0.5)
    _send(chan, f"vlan {vlan_id}", wait=0.5)
    if name:
        _send(chan, f"name {name}", wait=0.5)
    _send(chan, "exit", wait=0.5)
    _send(chan, "end", wait=0.5)
    _send(chan, "write memory", wait=3.0)

    if not vlan_exists(chan, vlan_id):
        log.error("VLAN %s not found after provisioning", vlan_id)
        return False
    log.info("VLAN %s provisioned successfully", vlan_id)
    return True


def load_vlan_file(path):
    entries = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            entries.append(
                {
                    "vlan_id": int(row["vlan_id"]),
                    "name": row.get("name", "").strip() or None,
                    "action": row.get("action", "add").strip().lower(),
                }
            )
    return entries


def parse_args():
    p = argparse.ArgumentParser(
        description="Provision VLANs on Cisco IOS switches via SSH"
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=15, help="SSH connect timeout (s)")

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--vlan", type=int, metavar="ID", help="Single VLAN ID")
    mode.add_argument("--vlan-file", metavar="CSV", help="CSV file: vlan_id,name,action")

    p.add_argument("--name", help="VLAN name (single-VLAN mode only)")
    p.add_argument(
        "--action",
        choices=["add", "remove"],
        default="add",
        help="Single-VLAN mode action (default: add)",
    )
    return p.parse_args()


def main():
    args = parse_args()

    if args.vlan_file:
        try:
            vlans = load_vlan_file(args.vlan_file)
        except (FileNotFoundError, KeyError) as exc:
            log.error("Failed to read VLAN file: %s", exc)
            sys.exit(1)
    else:
        vlans = [{"vlan_id": args.vlan, "name": args.name, "action": args.action}]

    log.info("Connecting to %s:%s", args.host, args.port)
    try:
        client, chan = open_shell(
            args.host, args.username, args.password, args.port, args.timeout
        )
    except Exception as exc:
        log.error("SSH connection failed: %s", exc)
        sys.exit(1)

    failures = 0
    try:
        for entry in vlans:
            ok = provision_vlan(chan, entry["vlan_id"], entry["name"], entry["action"])
            if not ok:
                failures += 1
    finally:
        chan.close()
        client.close()

    if failures:
        log.error("%d VLAN operation(s) failed", failures)
        sys.exit(1)
    log.info("All VLAN operations completed successfully")


if __name__ == "__main__":
    main()
```