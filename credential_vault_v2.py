The write was blocked — the user asked for script content output only anyway. Here's the complete script:

```
"""
credential_vault_v3.py - Encrypted credential vault with SSH key support and live validation.

Stores device credentials encrypted on disk using Fernet (AES-128-CBC). Supports both
password and SSH private-key authentication. Validates credentials against live devices
via Paramiko and updates stored entries after confirmed password rotations.

Usage:
    # Add password-based entry
    python credential_vault_v3.py add --device 192.168.1.1 --username admin --password s3cr3t

    # Add SSH key entry
    python credential_vault_v3.py add --device 192.168.1.1 --username admin --key ~/.ssh/id_rsa

    # Validate credentials against all stored devices
    python credential_vault_v3.py validate

    # Validate a single device
    python credential_vault_v3.py validate --device 192.168.1.1

    # Update stored password after rotating it on the device
    python credential_vault_v3.py rotate --device 192.168.1.1 --new-password N3wP@ss

    # List stored devices (credentials masked)
    python credential_vault_v3.py list

    # Export vault manifest as JSON or CSV (passwords never included)
    python credential_vault_v3.py export --format json

    # Remove an entry
    python credential_vault_v3.py delete --device 192.168.1.1

Prerequisites:
    pip install paramiko cryptography
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import paramiko
from cryptography.fernet import Fernet, InvalidToken

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_VAULT_PATH = Path.home() / ".ssh" / "net_vault.enc"
DEFAULT_KEY_PATH = Path.home() / ".ssh" / "net_vault.key"
DEFAULT_PORT = 22
DEFAULT_TIMEOUT = 10


def _get_fernet(key_path: Path) -> Fernet:
    if key_path.exists():
        return Fernet(key_path.read_bytes())
    key = Fernet.generate_key()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    logger.info("New vault key created: %s", key_path)
    return Fernet(key)


def _load_vault(vault_path: Path, fernet: Fernet) -> dict:
    if not vault_path.exists():
        return {}
    try:
        return json.loads(fernet.decrypt(vault_path.read_bytes()))
    except InvalidToken:
        logger.error("Vault decryption failed — wrong key or corrupted file")
        sys.exit(1)


def _save_vault(vault_path: Path, fernet: Fernet, data: dict) -> None:
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.write_bytes(fernet.encrypt(json.dumps(data).encode()))
    vault_path.chmod(0o600)


def _connect(host: str, port: int, username: str,
             password: Optional[str], key_path: Optional[str],
             timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # acceptable in closed lab nets
    kwargs = dict(hostname=host, port=port, username=username,
                  timeout=timeout, allow_agent=False, look_for_keys=False)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _entry_connect(host: str, entry: dict, timeout: int) -> paramiko.SSHClient:
    return _connect(
        host=host,
        port=entry.get("port", DEFAULT_PORT),
        username=entry["username"],
        password=entry.get("password"),
        key_path=entry.get("key_path"),
        timeout=timeout,
    )


# ---------- subcommand handlers ----------

def cmd_add(args, vault: dict) -> bool:
    if not args.password and not args.key:
        logger.error("Provide --password or --key")
        sys.exit(1)
    entry = {"username": args.username, "port": args.port,
             "auth_type": "key" if args.key else "password"}
    if args.password:
        entry["password"] = args.password
    if args.key:
        entry["key_path"] = str(Path(args.key).expanduser())
    vault[args.device] = entry
    logger.info("Stored credentials for %s (%s)", args.device, entry["auth_type"])
    return True


def cmd_validate(args, vault: dict) -> bool:
    devices = [args.device] if args.device else list(vault.keys())
    if not devices:
        logger.info("Vault is empty — nothing to validate")
        return True
    ok = failed = 0
    for host in devices:
        if host not in vault:
            logger.warning("No entry for %s", host)
            continue
        try:
            _entry_connect(host, vault[host], args.timeout).close()
            logger.info("%-22s OK", host)
            ok += 1
        except paramiko.AuthenticationException:
            logger.warning("%-22s AUTH FAILED", host)
            failed += 1
        except Exception as exc:
            logger.error("%-22s ERROR: %s", host, exc)
            failed += 1
    logger.info("Result: %d ok, %d failed out of %d", ok, failed, len(devices))
    return failed == 0


def cmd_rotate(args, vault: dict) -> bool:
    """Verify the new password works against the device, then update the vault."""
    if args.device not in vault:
        logger.error("No entry for %s", args.device)
        sys.exit(1)
    entry = vault[args.device]
    if entry.get("auth_type") == "key":
        logger.error("Password rotation is not applicable to key-based entries")
        sys.exit(1)
    try:
        _connect(args.device, entry.get("port", DEFAULT_PORT),
                 entry["username"], args.new_password, None, args.timeout).close()
        vault[args.device]["password"] = args.new_password
        logger.info("New password verified and stored for %s@%s",
                    entry["username"], args.device)
        return True
    except paramiko.AuthenticationException:
        logger.error("New password rejected by %s — vault NOT updated", args.device)
        sys.exit(1)
    except Exception as exc:
        logger.error("Could not reach %s: %s", args.device, exc)
        sys.exit(1)


def cmd_list(args, vault: dict) -> bool:
    if not vault:
        print("Vault is empty.")
        return True
    fmt = "{:<22} {:<16} {:<6} {}"
    print(fmt.format("Device", "Username", "Port", "Auth"))
    print("-" * 52)
    for host, e in sorted(vault.items()):
        print(fmt.format(host, e.get("username", "?"),
                         e.get("port", DEFAULT_PORT), e.get("auth_type", "?")))
    return True


def cmd_export(args, vault: dict) -> bool:
    safe = {h: {k: ("***" if k == "password" else v) for k, v in e.items()}
            for h, e in vault.items()}
    if args.format == "json":
        print(json.dumps(safe, indent=2))
    else:
        print("device,username,port,auth_type")
        for host, e in sorted(safe.items()):
            print(f"{host},{e.get('username','')},{e.get('port', DEFAULT_PORT)},{e.get('auth_type','')}")
    return True


def cmd_delete(args, vault: dict) -> bool:
    if args.device not in vault:
        logger.warning("No entry for %s", args.device)
        return True
    del vault[args.device]
    logger.info("Deleted credentials for %s", args.device)
    return True


# ---------- CLI ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Encrypted network credential vault")
    p.add_argument("--vault", default=str(DEFAULT_VAULT_PATH))
    p.add_argument("--key-file", default=str(DEFAULT_KEY_PATH))
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("add", help="Add or overwrite a credential entry")
    a.add_argument("--device", required=True)
    a.add_argument("--username", required=True)
    a.add_argument("--password")
    a.add_argument("--key", metavar="PATH", help="SSH private key file")
    a.add_argument("--port", type=int, default=DEFAULT_PORT)

    v = sub.add_parser("validate", help="Test credentials against device(s)")
    v.add_argument("--device", help="Single host (default: all)")
    v.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    r = sub.add_parser("rotate", help="Verify new password then update vault")
    r.add_argument("--device", required=True)
    r.add_argument("--new-password", required=True)
    r.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    sub.add_parser("list", help="List stored devices (no secrets shown)")

    e = sub.add_parser("export", help="Export manifest with passwords masked")
    e.add_argument("--format", choices=["json", "csv"], default="json")

    d = sub.add_parser("delete", help="Remove a credential entry")
    d.add_argument("--device", required=True)

    return p


MUTATING = {"add", "rotate", "delete"}
HANDLERS = {
    "add": cmd_add, "validate": cmd_validate, "rotate": cmd_rotate,
    "list": cmd_list, "export": cmd_export, "delete": cmd_delete,
}

if __name__ == "__main__":
    args = build_parser().parse_args()
    fernet = _get_fernet(Path(args.key_file).expanduser())
    vault_path = Path(args.vault).expanduser()
    vault = _load_vault(vault_path, fernet)

    HANDLERS[args.command](args, vault)

    if args.command in MUTATING:
        _save_vault(vault_path, fernet, vault)
```

Key differentiators from v1/v2: Fernet encryption at rest, SSH private key auth support alongside passwords, and the `rotate` subcommand validates the new credential against the live device before updating the vault (so you never store a wrong password after a failed rotation).