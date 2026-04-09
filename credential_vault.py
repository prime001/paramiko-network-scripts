```python
"""
credential_vault.py - Secure credential storage and retrieval for network devices.

Purpose:
    Provides an encrypted local credential store for network device authentication,
    eliminating plaintext passwords in scripts and environment variables. Credentials
    are encrypted with a master password using Fernet symmetric encryption and stored
    in a JSON vault file.

Usage:
    # Add credentials for a device
    python credential_vault.py add --host 192.168.1.1 --username admin

    # Test SSH connectivity using stored credentials
    python credential_vault.py test --host 192.168.1.1

    # List stored hosts
    python credential_vault.py list

    # Delete credentials for a host
    python credential_vault.py delete --host 192.168.1.1

Prerequisites:
    pip install paramiko cryptography
"""

import argparse
import getpass
import json
import logging
import os
import sys

import paramiko
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

DEFAULT_VAULT = os.path.expanduser("~/.net_credential_vault.json")
SSH_TIMEOUT = 10


def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def _load_vault(vault_path: str) -> dict:
    if not os.path.exists(vault_path):
        return {"salt": None, "credentials": {}}
    with open(vault_path, "r") as f:
        return json.load(f)


def _save_vault(vault_path: str, data: dict) -> None:
    with open(vault_path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(vault_path, 0o600)


def _get_fernet(master_password: str, vault: dict) -> Fernet:
    if vault["salt"] is None:
        salt = os.urandom(16)
        vault["salt"] = base64.b64encode(salt).decode()
    else:
        salt = base64.b64decode(vault["salt"])
    key = _derive_key(master_password, salt)
    return Fernet(key)


def cmd_add(args: argparse.Namespace) -> int:
    password = getpass.getpass(f"Device password for {args.username}@{args.host}: ")
    master = getpass.getpass("Master vault password: ")
    confirm = getpass.getpass("Confirm master vault password: ")
    if master != confirm:
        log.error("Master passwords do not match.")
        return 1

    vault = _load_vault(args.vault)
    fernet = _get_fernet(master, vault)
    encrypted = fernet.encrypt(password.encode()).decode()
    vault["credentials"][args.host] = {
        "username": args.username,
        "password": encrypted,
        "port": args.port,
    }
    _save_vault(args.vault, vault)
    log.info("Credentials stored for %s.", args.host)
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    vault = _load_vault(args.vault)
    if args.host not in vault["credentials"]:
        log.error("No credentials found for %s.", args.host)
        return 1
    del vault["credentials"][args.host]
    _save_vault(args.vault, vault)
    log.info("Credentials removed for %s.", args.host)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    vault = _load_vault(args.vault)
    hosts = vault.get("credentials", {})
    if not hosts:
        print("Vault is empty.")
        return 0
    print(f"{'HOST':<30} {'USERNAME':<20} {'PORT'}")
    print("-" * 60)
    for host, creds in sorted(hosts.items()):
        print(f"{host:<30} {creds['username']:<20} {creds.get('port', 22)}")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    vault = _load_vault(args.vault)
    if args.host not in vault.get("credentials", {}):
        log.error("No credentials found for %s. Run 'add' first.", args.host)
        return 1

    master = getpass.getpass("Master vault password: ")
    fernet = _get_fernet(master, vault)

    entry = vault["credentials"][args.host]
    try:
        password = fernet.decrypt(entry["password"].encode()).decode()
    except InvalidToken:
        log.error("Invalid master password.")
        return 1

    port = entry.get("port", 22)
    username = entry["username"]
    log.info("Testing SSH connectivity to %s:%s as %s ...", args.host, port, username)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=args.host,
            port=port,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, _ = client.exec_command("show version | include Software")
        output = stdout.read().decode().strip()
        log.info("Connection successful.")
        if output:
            print(output)
        return 0
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s.", args.host)
        return 1
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        return 1
    except OSError as exc:
        log.error("Network error: %s", exc)
        return 1
    finally:
        client.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypted credential vault for network devices."
    )
    parser.add_argument(
        "--vault",
        default=DEFAULT_VAULT,
        help=f"Path to vault file (default: {DEFAULT_VAULT})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    add_p = sub.add_parser("add", help="Store credentials for a host")
    add_p.add_argument("--host", required=True, help="Device hostname or IP")
    add_p.add_argument("--username", required=True, help="SSH username")
    add_p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

    del_p = sub.add_parser("delete", help="Remove credentials for a host")
    del_p.add_argument("--host", required=True, help="Device hostname or IP")

    sub.add_parser("list", help="List all stored hosts")

    test_p = sub.add_parser("test", help="Test SSH connectivity using stored credentials")
    test_p.add_argument("--host", required=True, help="Device hostname or IP")

    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "add": cmd_add,
        "delete": cmd_delete,
        "list": cmd_list,
        "test": cmd_test,
    }
    sys.exit(dispatch[args.command](args))
```