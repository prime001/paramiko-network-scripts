```python
"""
credential_vault.py - Encrypted Credential Storage for Network Devices

Purpose:
    Provides a secure, file-based credential vault for storing and retrieving
    network device credentials. Credentials are encrypted using Fernet symmetric
    encryption (via the cryptography library) and stored in a local JSON vault
    file. Integrates with paramiko to test stored credentials against live devices.

Usage:
    # Store credentials for a device
    python credential_vault.py store --device 192.168.1.1 --username admin

    # Retrieve and test credentials against a device
    python credential_vault.py test --device 192.168.1.1

    # List all stored device entries
    python credential_vault.py list

    # Remove credentials for a device
    python credential_vault.py remove --device 192.168.1.1

Prerequisites:
    pip install paramiko cryptography
    Set VAULT_MASTER_KEY env var, or let the script generate and display one.
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

DEFAULT_VAULT_PATH = Path.home() / ".network_vault.json"
DEFAULT_PORT = 22
SALT = b"network_vault_salt_v1"


def derive_fernet_key(master_password: str) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)


def load_vault(vault_path: Path) -> dict:
    if not vault_path.exists():
        return {}
    with vault_path.open("r") as f:
        return json.load(f)


def save_vault(vault: dict, vault_path: Path) -> None:
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.chmod(0o600) if vault_path.exists() else None
    with vault_path.open("w") as f:
        json.dump(vault, f, indent=2)
    vault_path.chmod(0o600)
    log.debug("Vault saved to %s", vault_path)


def cmd_store(args, fernet: Fernet, vault_path: Path) -> int:
    password = getpass.getpass(f"Password for {args.username}@{args.device}: ")
    if not password:
        log.error("Password cannot be empty.")
        return 1

    vault = load_vault(vault_path)
    encrypted = fernet.encrypt(password.encode()).decode()
    vault[args.device] = {
        "username": args.username,
        "password_enc": encrypted,
        "port": args.port,
    }
    save_vault(vault, vault_path)
    log.info("Credentials stored for %s.", args.device)
    return 0


def cmd_test(args, fernet: Fernet, vault_path: Path) -> int:
    vault = load_vault(vault_path)
    entry = vault.get(args.device)
    if not entry:
        log.error("No credentials found for %s. Run 'store' first.", args.device)
        return 1

    try:
        password = fernet.decrypt(entry["password_enc"].encode()).decode()
    except InvalidToken:
        log.error("Failed to decrypt credentials — wrong master key?")
        return 1

    username = entry["username"]
    port = entry.get("port", DEFAULT_PORT)
    log.info("Testing SSH connection to %s:%s as %s ...", args.device, port, username)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=args.device,
            port=port,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        transport = client.get_transport()
        peer = transport.getpeername() if transport else (args.device, port)
        log.info("SUCCESS — authenticated to %s:%s", peer[0], peer[1])

        stdin, stdout, stderr = client.exec_command("show version | head -3", timeout=10)
        output = stdout.read().decode(errors="replace").strip()
        if output:
            log.info("Device response:\n%s", output)
        return 0
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s.", username, args.device)
        return 1
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", args.device, exc)
        return 1
    except OSError as exc:
        log.error("Network error connecting to %s: %s", args.device, exc)
        return 1
    finally:
        client.close()


def cmd_list(args, fernet: Fernet, vault_path: Path) -> int:
    vault = load_vault(vault_path)
    if not vault:
        log.info("Vault is empty.")
        return 0
    print(f"{'Device':<20} {'Username':<20} {'Port'}")
    print("-" * 50)
    for device, entry in sorted(vault.items()):
        print(f"{device:<20} {entry['username']:<20} {entry.get('port', DEFAULT_PORT)}")
    return 0


def cmd_remove(args, fernet: Fernet, vault_path: Path) -> int:
    vault = load_vault(vault_path)
    if args.device not in vault:
        log.error("No entry for %s.", args.device)
        return 1
    del vault[args.device]
    save_vault(vault, vault_path)
    log.info("Removed credentials for %s.", args.device)
    return 0


def get_fernet() -> Fernet:
    master = os.environ.get("VAULT_MASTER_KEY")
    if not master:
        master = getpass.getpass("Vault master password: ")
    if not master:
        log.error("Master password required.")
        sys.exit(1)
    return derive_fernet_key(master)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypted credential vault for network devices."
    )
    parser.add_argument(
        "--vault",
        default=str(DEFAULT_VAULT_PATH),
        help=f"Path to vault file (default: {DEFAULT_VAULT_PATH})",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    store_p = sub.add_parser("store", help="Store credentials for a device")
    store_p.add_argument("--device", required=True, help="Device hostname or IP")
    store_p.add_argument("--username", required=True, help="SSH username")
    store_p.add_argument("--port", type=int, default=DEFAULT_PORT, help="SSH port")

    test_p = sub.add_parser("test", help="Test stored credentials against a device")
    test_p.add_argument("--device", required=True, help="Device hostname or IP")

    sub.add_parser("list", help="List all stored device entries")

    remove_p = sub.add_parser("remove", help="Remove credentials for a device")
    remove_p.add_argument("--device", required=True, help="Device hostname or IP")

    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    fernet = get_fernet()
    vault_path = Path(args.vault)

    commands = {
        "store": cmd_store,
        "test": cmd_test,
        "list": cmd_list,
        "remove": cmd_remove,
    }

    sys.exit(commands[args.command](args, fernet, vault_path))
```