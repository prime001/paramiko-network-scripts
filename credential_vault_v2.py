Credential Vault v3 - SSH Credential Rotation Tracker with Live Verification

Extends credential vault functionality with rotation scheduling and live
SSH verification via paramiko. Tracks credential age, flags stale entries,
and validates credentials against real devices before committing to vault.

Usage:
    python credential_vault_v3.py --add --host 192.168.1.1 --username admin
    python credential_vault_v3.py --verify --host 192.168.1.1
    python credential_vault_v3.py --rotate --host 192.168.1.1 --username admin
    python credential_vault_v3.py --list [--stale-days 90]
    python credential_vault_v3.py --delete --host 192.168.1.1

Prerequisites:
    pip install paramiko cryptography
    VAULT_KEY env var or --vault-key arg sets the Fernet encryption key.
    Generate a key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import argparse
import getpass
import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

import paramiko
from cryptography.fernet import Fernet, InvalidToken

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

DEFAULT_VAULT_PATH = Path.home() / ".network_vault_v3.enc"
DEFAULT_PORT = 22
DEFAULT_TIMEOUT = 10
DEFAULT_STALE_DAYS = 90


def load_vault(vault_path: Path, fernet: Fernet) -> dict:
    if not vault_path.exists():
        return {}
    try:
        encrypted = vault_path.read_bytes()
        return json.loads(fernet.decrypt(encrypted))
    except InvalidToken:
        log.error("Invalid vault key -- cannot decrypt vault.")
        sys.exit(1)


def save_vault(vault_path: Path, fernet: Fernet, data: dict) -> None:
    encrypted = fernet.encrypt(json.dumps(data).encode())
    vault_path.write_bytes(encrypted)
    vault_path.chmod(0o600)


def verify_ssh(host: str, username: str, password: str, port: int, timeout: int) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        log.info("SSH verification succeeded for %s@%s:%d", username, host, port)
        return True
    except paramiko.AuthenticationException:
        log.warning("Authentication failed for %s@%s", username, host)
        return False
    except (socket.timeout, paramiko.ssh_exception.NoValidConnectionsError, OSError) as exc:
        log.warning("Connection failed for %s: %s", host, exc)
        return False
    finally:
        client.close()


def cmd_add(args, vault: dict, fernet: Fernet, vault_path: Path) -> None:
    password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
    if args.verify_live:
        if not verify_ssh(args.host, args.username, password, args.port, args.timeout):
            log.error("Live verification failed -- credential not stored.")
            sys.exit(1)
    vault[args.host] = {
        "username": args.username,
        "password": password,
        "port": args.port,
        "added": datetime.now(timezone.utc).isoformat(),
        "last_rotated": datetime.now(timezone.utc).isoformat(),
        "verified": args.verify_live,
    }
    save_vault(vault_path, fernet, vault)
    log.info("Stored credentials for %s", args.host)


def cmd_verify(args, vault: dict) -> None:
    entry = vault.get(args.host)
    if not entry:
        log.error("No credentials found for %s", args.host)
        sys.exit(1)
    ok = verify_ssh(
        args.host, entry["username"], entry["password"], entry["port"], args.timeout
    )
    sys.exit(0 if ok else 1)


def cmd_rotate(args, vault: dict, fernet: Fernet, vault_path: Path) -> None:
    if args.host not in vault:
        log.error("No credentials found for %s -- use --add first.", args.host)
        sys.exit(1)
    new_password = getpass.getpass(f"New password for {args.username}@{args.host}: ")
    if args.verify_live:
        if not verify_ssh(args.host, args.username, new_password, args.port, args.timeout):
            log.error("Live verification failed -- credential not rotated.")
            sys.exit(1)
    vault[args.host].update(
        {
            "username": args.username,
            "password": new_password,
            "last_rotated": datetime.now(timezone.utc).isoformat(),
            "verified": args.verify_live,
        }
    )
    save_vault(vault_path, fernet, vault)
    log.info("Rotated credentials for %s", args.host)


def cmd_list(args, vault: dict) -> None:
    if not vault:
        print("Vault is empty.")
        return
    now = datetime.now(timezone.utc)
    print(f"{'Host':<20} {'Username':<16} {'Port':<6} {'Last Rotated':<22} {'Status'}")
    print("-" * 80)
    for host, entry in sorted(vault.items()):
        rotated = datetime.fromisoformat(entry["last_rotated"])
        age_days = (now - rotated).days
        status = f"STALE ({age_days}d)" if age_days >= args.stale_days else f"OK ({age_days}d)"
        print(
            f"{host:<20} {entry['username']:<16} {entry['port']:<6} "
            f"{entry['last_rotated'][:19]:<22} {status}"
        )


def cmd_delete(args, vault: dict, fernet: Fernet, vault_path: Path) -> None:
    if args.host not in vault:
        log.error("No credentials found for %s", args.host)
        sys.exit(1)
    del vault[args.host]
    save_vault(vault_path, fernet, vault)
    log.info("Deleted credentials for %s", args.host)


def build_fernet(args) -> Fernet:
    key = args.vault_key or os.environ.get("VAULT_KEY")
    if not key:
        log.error("Provide --vault-key or set VAULT_KEY environment variable.")
        sys.exit(1)
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        log.error(
            "Invalid Fernet key. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network credential vault with rotation tracking and SSH verification"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--add", action="store_true", help="Add or overwrite credentials")
    group.add_argument("--verify", action="store_true", help="Verify stored credentials via SSH")
    group.add_argument("--rotate", action="store_true", help="Rotate credentials for a host")
    group.add_argument("--list", action="store_true", help="List all stored credentials")
    group.add_argument("--delete", action="store_true", help="Remove credentials for a host")

    parser.add_argument("--host", help="Device hostname or IP")
    parser.add_argument("--username", help="SSH username")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Connection timeout seconds")
    parser.add_argument("--vault-path", type=Path, default=DEFAULT_VAULT_PATH, help="Vault file path")
    parser.add_argument("--vault-key", help="Fernet encryption key (or set VAULT_KEY env var)")
    parser.add_argument("--verify-live", action="store_true", help="Test credentials against device before storing")
    parser.add_argument(
        "--stale-days",
        type=int,
        default=DEFAULT_STALE_DAYS,
        help="Days before credential flagged stale (default: 90)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    fernet = build_fernet(args)
    vault = load_vault(args.vault_path, fernet)

    if args.add:
        if not args.host or not args.username:
            log.error("--add requires --host and --username")
            sys.exit(1)
        cmd_add(args, vault, fernet, args.vault_path)
    elif args.verify:
        if not args.host:
            log.error("--verify requires --host")
            sys.exit(1)
        cmd_verify(args, vault)
    elif args.rotate:
        if not args.host or not args.username:
            log.error("--rotate requires --host and --username")
            sys.exit(1)
        cmd_rotate(args, vault, fernet, args.vault_path)
    elif args.list:
        cmd_list(args, vault)
    elif args.delete:
        if not args.host:
            log.error("--delete requires --host")
            sys.exit(1)
        cmd_delete(args, vault, fernet, args.vault_path)