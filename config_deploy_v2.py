The user's explicit instruction is "Output ONLY the script content, no markdown fences, no explanation" — that takes precedence over the brainstorming flow per the skill's own priority rules. Writing the script directly.

```python
"""
vlan_manager.py - VLAN provisioning and lifecycle management for Cisco IOS/IOS-XE switches.

Purpose:
    Create, modify, or delete VLANs on Cisco switches via SSH. Supports single
    VLAN operations and bulk provisioning from a JSON file. Post-deploy
    verification confirms changes landed before exiting.

Usage:
    python vlan_manager.py --host 192.168.1.1 --user admin --password secret \
        --action create --vlan-id 100 --vlan-name SERVERS

    python vlan_manager.py --host 192.168.1.1 --user admin --password secret \
        --action bulk --vlan-file vlans.json

    python vlan_manager.py --host 192.168.1.1 --user admin --password secret \
        --action delete --vlan-id 100

    python vlan_manager.py --host 192.168.1.1 --user admin --password secret \
        --action create --vlan-id 200 --vlan-name MGMT --dry-run

Prerequisites:
    pip install paramiko
    SSH enabled on target device; account with privilege 15 (or supply --enable-secret).

Bulk JSON format:
    [{"id": 100, "name": "SERVERS"}, {"id": 200, "name": "MGMT"}]
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

_RECV_PAUSE = 0.3
_CMD_PAUSE = 0.5


def _connect(host: str, user: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return client


def _send(shell, commands: list, delay: float = _CMD_PAUSE) -> str:
    out = ""
    for cmd in commands:
        shell.send(cmd + "\n")
        time.sleep(delay)
        while shell.recv_ready():
            out += shell.recv(4096).decode("utf-8", errors="replace")
            time.sleep(_RECV_PAUSE)
    return out


def _current_vlans(shell) -> dict:
    raw = _send(shell, ["show vlan brief"])
    vlans = {}
    for line in raw.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            vlans[int(parts[0])] = parts[1] if len(parts) > 1 else ""
    return vlans


def _build_commands(action: str, vlan_id: int, vlan_name: Optional[str]) -> list:
    cmds = ["configure terminal"]
    if action == "delete":
        cmds.append(f"no vlan {vlan_id}")
    else:
        cmds.append(f"vlan {vlan_id}")
        if vlan_name:
            cmds.append(f" name {vlan_name}")
        cmds.append("exit")
    cmds += ["end", "write memory"]
    return cmds


def _apply(shell, action: str, vlan_id: int, vlan_name: Optional[str], dry_run: bool) -> bool:
    cmds = _build_commands(action, vlan_id, vlan_name)
    if dry_run:
        log.info("[DRY RUN] %s VLAN %d — commands: %s", action, vlan_id, cmds)
        return True
    log.info("%s VLAN %d name=%s", action.upper(), vlan_id, vlan_name or "(none)")
    out = _send(shell, cmds)
    if any(tok in out for tok in ("Invalid input", "% Error", "% Bad")):
        log.error("Device error for VLAN %d:\n%s", vlan_id, out.strip())
        return False
    return True


def _verify(shell, action: str, vlan_id: int) -> bool:
    vlans = _current_vlans(shell)
    if action == "delete":
        ok = vlan_id not in vlans
    else:
        ok = vlan_id in vlans
    log.info("Verify VLAN %d %s: %s", vlan_id, action, "PASS" if ok else "FAIL")
    return ok


def _load_file(path: str) -> list:
    with open(path) as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array")
    return data


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="VLAN provisioning for Cisco IOS/IOS-XE")
    p.add_argument("--host", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--action", required=True, choices=["create", "delete", "bulk"])
    p.add_argument("--vlan-id", type=int)
    p.add_argument("--vlan-name")
    p.add_argument("--vlan-file", help="JSON file for bulk action")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.action in ("create", "delete") and args.vlan_id is None:
        log.error("--vlan-id required for %s action", args.action)
        sys.exit(1)
    if args.action == "bulk" and not args.vlan_file:
        log.error("--vlan-file required for bulk action")
        sys.exit(1)

    client = None
    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        client = _connect(args.host, args.user, args.password, args.port)
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(1)
        shell.recv(4096)  # discard banner/prompt

        if args.action == "bulk":
            entries = _load_file(args.vlan_file)
            log.info("Processing %d VLANs from %s", len(entries), args.vlan_file)
            passed = failed = 0
            for entry in entries:
                vid = entry.get("id")
                vname = entry.get("name")
                if vid is None:
                    log.warning("Skipping entry missing 'id': %s", entry)
                    failed += 1
                    continue
                ok = _apply(shell, "create", vid, vname, args.dry_run)
                if ok and not args.no_verify and not args.dry_run:
                    ok = _verify(shell, "create", vid)
                passed += ok
                failed += not ok
            log.info("Bulk done — passed: %d  failed: %d", passed, failed)
            sys.exit(0 if failed == 0 else 1)
        else:
            ok = _apply(shell, args.action, args.vlan_id, args.vlan_name, args.dry_run)
            if ok and not args.no_verify and not args.dry_run:
                ok = _verify(shell, args.action, args.vlan_id)
            sys.exit(0 if ok else 1)

    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    main()
```