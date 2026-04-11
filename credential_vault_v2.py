The user has given explicit instructions: "Output ONLY the script content, no markdown fences, no explanation." The brainstorming skill's design process would violate that direct instruction. Per the skill's own guidance, user instructions take precedence over skill workflow. Proceeding directly with the output.

#!/usr/bin/env python3
"""
credential_vault.py - Encrypted Network Device Credential Manager

Purpose:
    Securely stores, retrieves, and manages SSH credentials for network devices
    using Fernet symmetric encryption backed by a PBKDF2-derived master password.
    Supports optional live SSH connectivity verification via Paramiko.

Usage:
    # Initialize a new encrypted vault
    python credential_vault.py init

    # Add credentials for a device
    python credential_vault.py add --device 192.168.1.1 --username admin

    # Retrieve stored credentials
    python credential_vault.py get --device 192.168.1.1

    # List all devices in the vault
    python credential_vault.py list

    # Delete a device entry
    python credential_vault.py delete --device 192.168.1.1

    # Test stored credentials against a live device over SSH
    python credential_vault.py verify --device 192.168.1.1

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

import paramiko

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("ERROR: cryptography package required.  Run: pip install cryptography")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

DEFAULT_VAULT_PATH = os.path.expanduser("~/.network_vault.enc")
DEFAULT_SALT_PATH = os.path.expanduser("~/.network_vault.salt")


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def _fernet_from_password(salt_path: str) -> Fernet:
    if not os.path.exists(salt_path):
        logger.error(
            "Vault not initialised. Run: python credential_vault.py init"
        )
        sys.exit(1)
    with open(salt_path, "rb") as fh:
        salt = fh.read()
    master_password = getpass.getpass("Master password: ")
    return Fernet(derive_key(master_password, salt))


def load_vault(vault_path: str, fernet: Fernet) -> dict:
    if not os.path.exists(vault_path):
        return {}
    try:
        with open(vault_path, "rb") as fh:
            return json.loads(fernet.decrypt(fh.read()).decode())
    except InvalidToken:
        logger.error("Wrong master password or vault is corrupted.")
        sys.exit(1)
    except Exception as exc:
        logger.error("Failed to load vault: %s", exc)
        sys.exit(1)


def save_vault(vault_path: str, fernet: Fernet, data: dict) -> None:
    try:
        encrypted = fernet.encrypt(json.dumps(data).encode())
        with open(vault_path, "wb") as fh:
            fh.write(encrypted)
        os.chmod(vault_path, 0o600)
    except Exception as exc:
        logger.error("Failed to save vault: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    if os.path.exists(args.vault):
        answer = input(f"Vault already exists at {args.vault}. Overwrite? [y/N]: ")
        if answer.lower() != "y":
            print("Aborted.")
            return

    pw = getpass.getpass("New master password: ")
    if pw != getpass.getpass("Confirm master password: "):
        logger.error("Passwords do not match.")
        sys.exit(1)

    salt = os.urandom(16)
    with open(args.salt, "wb") as fh:
        fh.write(salt)
    os.chmod(args.salt, 0o600)

    fernet = Fernet(derive_key(pw, salt))
    save_vault(args.vault, fernet, {})
    logger.info("Vault initialised at %s", args.vault)


def cmd_add(args: argparse.Namespace) -> None:
    fernet = _fernet_from_password(args.salt)
    vault = load_vault(args.vault, fernet)

    if args.device in vault and not args.force:
        answer = input(f"Entry for {args.device} already exists. Overwrite? [y/N]: ")
        if answer.lower() != "y":
            print("Aborted.")
            return

    password = getpass.getpass(f"SSH password for {args.username}@{args.device}: ")
    enable_secret: str | None = None
    if args.enable:
        secret = getpass.getpass("Enable/privileged secret (blank to skip): ")
        enable_secret = secret or None

    vault[args.device] = {
        "username": args.username,
        "password": password,
        "port": args.port,
        "enable_secret": enable_secret,
    }
    save_vault(args.vault, fernet, vault)
    logger.info("Credentials stored for %s", args.device)


def cmd_get(args: argparse.Namespace) -> None:
    fernet = _fernet_from_password(args.salt)
    vault = load_vault(args.vault, fernet)

    entry = vault.get(args.device)
    if not entry:
        logger.error("No entry found for %s", args.device)
        sys.exit(1)

    print(f"Device  : {args.device}")
    print(f"Username: {entry['username']}")
    print(f"Port    : {entry.get('port', 22)}")
    if args.show_password:
        print(f"Password: {entry['password']}")
        if entry.get("enable_secret"):
            print(f"Enable  : {entry['enable_secret']}")
    else:
        print("Password: [hidden] — pass --show-password to reveal")


def cmd_list(args: argparse.Namespace) -> None:
    fernet = _fernet_from_password(args.salt)
    vault = load_vault(args.vault, fernet)

    if not vault:
        print("Vault is empty.")
        return

    header = f"{'Device':<22} {'Username':<18} {'Port'}"
    print(header)
    print("-" * len(header))
    for device, entry in sorted(vault.items()):
        print(f"{device:<22} {entry['username']:<18} {entry.get('port', 22)}")
    print(f"\n{len(vault)} device(s) stored.")


def cmd_delete(args: argparse.Namespace) -> None:
    fernet = _fernet_from_password(args.salt)
    vault = load_vault(args.vault, fernet)

    if args.device not in vault:
        logger.error("No entry found for %s", args.device)
        sys.exit(1)

    if not args.yes:
        answer = input(f"Delete credentials for {args.device}? [y/N]: ")
        if answer.lower() != "y":
            print("Aborted.")
            return

    del vault[args.device]
    save_vault(args.vault, fernet, vault)
    logger.info("Credentials deleted for %s", args.device)


def cmd_verify(args: argparse.Namespace) -> None:
    fernet = _fernet_from_password(args.salt)
    vault = load_vault(args.vault, fernet)

    entry = vault.get(args.device)
    if not entry:
        logger.error("No entry found for %s", args.device)
        sys.exit(1)

    host = args.device
    port = entry.get("port", 22)
    username = entry["username"]
    password = entry["password"]

    logger.info("Testing SSH to %s:%d as %s …", host, port, username)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=args.timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, _ = client.exec_command("show version | include uptime", timeout=10)
        snippet = stdout.read().decode(errors="replace").strip()
        logger.info("Connection SUCCESSFUL to %s", host)
        if snippet:
            print(f"Device response: {snippet[:120]}")
    except paramiko.AuthenticationException:
        logger.error("Authentication FAILED for %s@%s", username, host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection FAILED to %s: %s", host, exc)
        sys.exit(1)
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypted credential vault for network devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--vault",
        default=DEFAULT_VAULT_PATH,
        metavar="PATH",
        help=f"Vault file location (default: {DEFAULT_VAULT_PATH})",
    )
    parser.add_argument(
        "--salt",
        default=DEFAULT_SALT_PATH,
        metavar="PATH",
        help=f"Salt file location (default: {DEFAULT_SALT_PATH})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialise a new encrypted vault")

    p_add = sub.add_parser("add", help="Add or update credentials for a device")
    p_add.add_argument("--device", required=True, help="Hostname or IP address")
    p_add.add_argument("--username", required=True, help="SSH username")
    p_add.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p_add.add_argument(
        "--enable", action="store_true", help="Prompt for privileged/enable secret"
    )
    p_add.add_argument(
        "--force", action="store_true", help="Overwrite existing entry without prompting"
    )

    p_get = sub.add_parser("get", help="Show stored credentials for a device")
    p_get.add_argument("--device", required=True, help="Hostname or IP address")
    p_get.add_argument(
        "--show-password", action="store_true", help="Print password in plaintext"
    )

    sub.add_parser("list", help="List all devices in the vault")

    p_del = sub.add_parser("delete", help="Remove credentials for a device")
    p_del.add_argument("--device", required=True, help="Hostname or IP address")
    p_del.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    p_ver = sub.add_parser("verify", help="Test stored credentials via live SSH")
    p_ver.add_argument("--device", required=True, help="Hostname or IP address")
    p_ver.add_argument(
        "--timeout", type=int, default=10, help="Connection timeout in seconds (default: 10)"
    )

    return parser


if __name__ == "__main__":
    _parser = build_parser()
    _args = _parser.parse_args()

    _dispatch = {
        "init": cmd_init,
        "add": cmd_add,
        "get": cmd_get,
        "list": cmd_list,
        "delete": cmd_delete,
        "verify": cmd_verify,
    }
    _dispatch[_args.command](_args)