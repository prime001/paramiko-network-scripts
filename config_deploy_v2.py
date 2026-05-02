The user's explicit instruction — "Output ONLY the script content" — overrides the brainstorming flow. Writing the script now.

```python
"""
vlan_provisioner.py — Bulk VLAN add/remove for Cisco IOS/IOS-XE switches.

Purpose:
    Reads a JSON file describing VLANs to create or delete, connects to one
    or more switches via SSH, validates current VLAN state, applies changes,
    and confirms the result.  Supports dry-run mode to preview commands
    before committing any change.

Usage:
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret \\
        --vlans vlans.json [--dry-run] [--port 22]

    python vlan_provisioner.py -d 10.0.0.1,10.0.0.2 -u admin \\
        --key ~/.ssh/id_rsa --vlans vlans.json

VLAN JSON format:
    {
        "add": [
            {"id": 100, "name": "CORP_DATA"},
            {"id": 200, "name": "CORP_VOICE"}
        ],
        "remove": [
            {"id": 999}
        ]
    }

Prerequisites:
    pip install paramiko
    SSH access with privilege level sufficient for global config mode.
"""

import argparse
import json
import logging
import sys
import time
from typing import Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def _open_shell(client: paramiko.SSHClient, timeout: int = 15) -> paramiko.Channel:
    shell = client.invoke_shell(width=200, height=50)
    shell.settimeout(timeout)
    time.sleep(1)
    shell.recv(4096)
    return shell


def _send(shell: paramiko.Channel, cmd: str, delay: float = 0.5) -> str:
    shell.send(cmd + "\n")
    time.sleep(delay)
    chunks = []
    while shell.recv_ready():
        chunks.append(shell.recv(4096))
    return b"".join(chunks).decode("utf-8", errors="replace")


def _existing_vlans(shell: paramiko.Channel) -> set:
    out = _send(shell, "show vlan brief", delay=1.2)
    ids = set()
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            ids.add(int(parts[0]))
    return ids


def _connect(
    host: str,
    port: int,
    username: str,
    password: Optional[str],
    key_path: Optional[str],
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(hostname=host, port=port, username=username, timeout=15)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def provision(
    shell: paramiko.Channel,
    add: list,
    remove: list,
    dry_run: bool,
    device: str,
) -> dict:
    tag = f"[{device}]"
    before = _existing_vlans(shell)
    log.info(f"{tag} Current VLANs: {sorted(before)}")

    cmds: list = []
    for v in add:
        vid = int(v["id"])
        if vid in before:
            log.info(f"{tag} VLAN {vid} exists — skip add")
            continue
        cmds.append(f"vlan {vid}")
        if v.get("name"):
            cmds.append(f" name {v['name']}")

    for v in remove:
        vid = int(v["id"])
        if vid not in before:
            log.info(f"{tag} VLAN {vid} absent — skip remove")
            continue
        cmds.append(f"no vlan {vid}")

    if not cmds:
        log.info(f"{tag} No changes required")
        return {"device": device, "status": "no_change", "commands": []}

    log.info(f"{tag} Pending commands:")
    for c in cmds:
        log.info(f"{tag}   {c}")

    if dry_run:
        log.info(f"{tag} Dry-run — not applied")
        return {"device": device, "status": "dry_run", "commands": cmds}

    _send(shell, "configure terminal", delay=0.5)
    for c in cmds:
        resp = _send(shell, c, delay=0.3)
        if "Invalid" in resp or "Error" in resp:
            log.warning(f"{tag} Unexpected response to '{c.strip()}': {resp.strip()}")
    _send(shell, "end", delay=0.5)
    _send(shell, "write memory", delay=3.0)

    after = _existing_vlans(shell)
    added = [v["id"] for v in add if int(v["id"]) in after and int(v["id"]) not in before]
    removed = [v["id"] for v in remove if int(v["id"]) not in after and int(v["id"]) in before]
    log.info(f"{tag} Added: {added}  Removed: {removed}")
    return {"device": device, "status": "ok", "added": added, "removed": removed}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision VLANs on Cisco IOS/IOS-XE switches"
    )
    parser.add_argument("-d", "--devices", required=True,
                        help="Comma-separated device IPs/hostnames")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", dest="key_path", default=None,
                        help="SSH private key path (alternative to password)")
    parser.add_argument("--vlans", required=True,
                        help="JSON file defining VLANs to add/remove")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands without applying them")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_path:
        parser.error("Provide --password or --key")

    try:
        with open(args.vlans) as fh:
            vlan_def = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.error(f"Cannot load VLAN file: {exc}")
        sys.exit(1)

    add = vlan_def.get("add", [])
    remove = vlan_def.get("remove", [])
    if not add and not remove:
        log.error("VLAN file has no 'add' or 'remove' entries")
        sys.exit(1)

    devices = [h.strip() for h in args.devices.split(",") if h.strip()]
    results = []

    for host in devices:
        log.info(f"Connecting to {host}:{args.port}")
        try:
            client = _connect(host, args.port, args.username, args.password, args.key_path)
            shell = _open_shell(client)
            _send(shell, "terminal length 0")
            result = provision(shell, add, remove, args.dry_run, host)
            results.append(result)
            client.close()
        except paramiko.AuthenticationException:
            log.error(f"[{host}] Authentication failed")
            results.append({"device": host, "status": "auth_error"})
        except (paramiko.SSHException, OSError) as exc:
            log.error(f"[{host}] Connection error: {exc}")
            results.append({"device": host, "status": "connection_error"})

    failed = [r for r in results if r["status"] not in ("ok", "no_change", "dry_run")]
    if failed:
        log.error(f"Failed: {[r['device'] for r in failed]}")
        sys.exit(1)
    log.info("All devices complete")


if __name__ == "__main__":
    main()
```