The write was blocked by permissions. Here is the complete script content as requested:

```
"""
credential_rotation.py — Rotate SSH credentials across network devices.

Purpose:
    Connect to each device in a vault JSON file using current credentials,
    change the password to a new value, verify the new credentials work,
    and write the updated vault back to disk.

Usage:
    python credential_rotation.py --vault creds.json --username admin \
        --new-password <new> [--devices 192.168.1.1 192.168.1.2] \
        [--port 22] [--timeout 30] [--dry-run]

Prerequisites:
    pip install paramiko
    Vault JSON format:
        {
            "192.168.1.1": {"username": "admin", "password": "oldpass"},
            ...
        }

    Target devices must support:
        - SSH access
        - IOS-style `username <user> privilege 15 secret <pass>` command
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def _send(shell, command: str, delay: float = 1.5) -> str:
    shell.send(command + "\n")
    time.sleep(delay)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode("utf-8", errors="replace")
    return output


def change_password(host: str, port: int, username: str, current_password: str,
                    new_password: str, timeout: int) -> bool:
    """
    Open an SSH shell to host, issue the password-change command, close.
    Returns True on success.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=current_password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell()
        time.sleep(1.0)
        shell.recv(4096)

        _send(shell, "enable")
        _send(shell, "conf t")
        _send(shell, f"username {username} privilege 15 secret {new_password}")
        _send(shell, "end")
        output = _send(shell, "write memory")

        if "%" in output:
            log.warning("%s: unexpected device error during write: %s", host, output.strip())
        return True

    except paramiko.AuthenticationException:
        log.error("%s: authentication failed with current credentials", host)
        return False
    except Exception as exc:
        log.error("%s: connection error: %s", host, exc)
        return False
    finally:
        client.close()


def verify_credentials(host: str, port: int, username: str,
                        password: str, timeout: int) -> bool:
    """Return True if SSH login succeeds with the given credentials."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as exc:
        log.error("%s: verification connection error: %s", host, exc)
        return False
    finally:
        client.close()


def rotate(vault_path: Path, username: str, new_password: str,
           devices: list[str] | None, port: int, timeout: int,
           dry_run: bool) -> int:
    """
    Rotate credentials for each device in the vault.
    Returns count of failures.
    """
    vault = json.loads(vault_path.read_text())

    targets = devices if devices else list(vault.keys())
    unknown = [h for h in targets if h not in vault]
    if unknown:
        log.error("Devices not in vault: %s", ", ".join(unknown))
        return len(unknown)

    failures = 0
    updated = dict(vault)

    for host in targets:
        entry = vault[host]
        current_user = username or entry.get("username")
        current_pass = entry.get("password", "")

        if dry_run:
            log.info("[dry-run] %s: would rotate password for user %s", host, current_user)
            continue

        log.info("%s: rotating credentials for user %s", host, current_user)

        ok = change_password(host, port, current_user, current_pass, new_password, timeout)
        if not ok:
            log.error("%s: password change failed — vault not updated", host)
            failures += 1
            continue

        log.info("%s: verifying new credentials ...", host)
        verified = verify_credentials(host, port, current_user, new_password, timeout)
        if not verified:
            log.error("%s: new credentials did not verify — manual recovery needed", host)
            failures += 1
            continue

        updated[host] = {"username": current_user, "password": new_password}
        log.info("%s: rotation complete", host)

    if not dry_run and updated != vault:
        vault_path.write_text(json.dumps(updated, indent=2))
        log.info("Vault written: %s", vault_path)

    return failures


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Rotate SSH credentials across network devices and update the vault."
    )
    p.add_argument("--vault", required=True, help="Path to vault JSON file")
    p.add_argument("--username", required=True, help="Account username to rotate")
    p.add_argument("--new-password", required=True, dest="new_password",
                   help="New password to set on all target devices")
    p.add_argument("--devices", nargs="+", metavar="HOST",
                   help="Limit rotation to these hosts (default: all in vault)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30,
                   help="Connection timeout in seconds (default: 30)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print what would happen without making changes")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    vault_path = Path(args.vault)
    if not vault_path.exists():
        log.error("Vault file not found: %s", vault_path)
        sys.exit(1)

    failures = rotate(
        vault_path=vault_path,
        username=args.username,
        new_password=args.new_password,
        devices=args.devices,
        port=args.port,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )

    if failures:
        log.error("%d device(s) failed — review logs before retrying", failures)
        sys.exit(1)

    log.info("All rotations complete")
```