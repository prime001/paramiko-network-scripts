The user's instruction is explicit: "Output ONLY the script content, no markdown fences, no explanation." That overrides the brainstorming flow — the spec is already fully defined.

"""
credential_vault_v3.py - Encrypted SSH credential vault with live validation.

Purpose:
    Stores network device credentials encrypted with a master-password-derived key
    (PBKDF2 + Fernet). Supports add, list, delete, and test (live SSH probe via
    paramiko) operations. Each entry holds username, password, and an optional
    enable secret. Vault file is chmod 600; master password is never stored.

Usage:
    python credential_vault_v3.py add  --device 192.168.1.1 --username admin
    python credential_vault_v3.py list
    python credential_vault_v3.py test --device 192.168.1.1
    python credential_vault_v3.py delete --device 192.168.1.1

    Set VAULT_MASTER_PASSWORD env var to avoid interactive prompts in scripts.

Prerequisites:
    pip install paramiko cryptography
"""

import argparse
import base64
import getpass
import json
import logging
import os
import sys
from pathlib import Path

import paramiko
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

DEFAULT_VAULT = Path.home() / ".netcreds" / "vault.json"
SALT_KEY = "__salt__"
SSH_TIMEOUT = 10


def _derive_key(master: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master.encode()))


def _load_vault(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path) as fh:
        return json.load(fh)


def _save_vault(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    os.chmod(path, 0o600)


def _get_master() -> str:
    return os.environ.get("VAULT_MASTER_PASSWORD") or getpass.getpass("Master password: ")


def _fernet(master: str, vault: dict) -> Fernet:
    if SALT_KEY not in vault:
        raise ValueError("Vault is empty — add a device first to initialize it")
    salt = base64.b64decode(vault[SALT_KEY])
    return Fernet(_derive_key(master, salt))


def cmd_add(args: argparse.Namespace, vault: dict, path: Path) -> None:
    master = args.master_password or _get_master()

    if SALT_KEY not in vault:
        salt = os.urandom(16)
        vault[SALT_KEY] = base64.b64encode(salt).decode()
    else:
        salt = base64.b64decode(vault[SALT_KEY])

    fern = Fernet(_derive_key(master, salt))
    password = args.password or getpass.getpass(f"SSH password for {args.device}: ")
    enable = ""
    if args.enable:
        enable = getpass.getpass(f"Enable secret for {args.device} (blank to skip): ")

    vault[args.device] = {
        "username": fern.encrypt(args.username.encode()).decode(),
        "password": fern.encrypt(password.encode()).decode(),
        "enable_secret": fern.encrypt(enable.encode()).decode(),
        "port": args.port,
    }
    _save_vault(path, vault)
    log.info("Stored credentials for %s (port %d)", args.device, args.port)


def cmd_list(args: argparse.Namespace, vault: dict, path: Path) -> None:
    devices = sorted(k for k in vault if k != SALT_KEY)
    if not devices:
        print("Vault is empty.")
        return
    print(f"{'Device':<30} {'Port':<8} Credentials")
    print("-" * 55)
    for device in devices:
        port = vault[device].get("port", 22)
        print(f"{device:<30} {port:<8} [encrypted]")


def cmd_delete(args: argparse.Namespace, vault: dict, path: Path) -> None:
    if args.device not in vault:
        log.error("No entry found for %s", args.device)
        sys.exit(1)
    del vault[args.device]
    _save_vault(path, vault)
    log.info("Deleted credentials for %s", args.device)


def cmd_test(args: argparse.Namespace, vault: dict, path: Path) -> None:
    if args.device not in vault:
        log.error("No entry found for %s", args.device)
        sys.exit(1)

    master = args.master_password or _get_master()
    try:
        fern = _fernet(master, vault)
    except ValueError as exc:
        log.error("%s", exc)
        sys.exit(1)

    entry = vault[args.device]
    try:
        username = fern.decrypt(entry["username"].encode()).decode()
        password = fern.decrypt(entry["password"].encode()).decode()
    except InvalidToken:
        log.error("Decryption failed — wrong master password")
        sys.exit(1)

    port = entry.get("port", 22)
    log.info("Probing %s:%d as %s ...", args.device, port, username)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            args.device,
            port=port,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        log.info("SUCCESS — credentials valid for %s", args.device)
    except paramiko.AuthenticationException:
        log.error("FAILED — authentication rejected by %s", args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("FAILED — %s", exc)
        sys.exit(1)
    finally:
        client.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Encrypted SSH credential vault for network devices")
    p.add_argument("--vault", default=str(DEFAULT_VAULT), metavar="PATH",
                   help="Vault file path (default: ~/.netcreds/vault.json)")
    p.add_argument("--master-password", metavar="PWD",
                   help="Master password (prefer VAULT_MASTER_PASSWORD env var)")

    sub = p.add_subparsers(dest="command", required=True)

    add_p = sub.add_parser("add", help="Store credentials for a device")
    add_p.add_argument("--device", required=True, help="Hostname or IP")
    add_p.add_argument("--username", required=True, help="SSH username")
    add_p.add_argument("--password", help="SSH password (prompted if omitted)")
    add_p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    add_p.add_argument("--enable", action="store_true", help="Prompt for enable secret")

    sub.add_parser("list", help="Show all devices in the vault")

    del_p = sub.add_parser("delete", help="Remove a device entry")
    del_p.add_argument("--device", required=True)

    test_p = sub.add_parser("test", help="Validate stored credentials via live SSH")
    test_p.add_argument("--device", required=True)

    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    vault_path = Path(args.vault)
    vault = _load_vault(vault_path)
    {"add": cmd_add, "list": cmd_list, "delete": cmd_delete, "test": cmd_test}[
        args.command
    ](args, vault, vault_path)