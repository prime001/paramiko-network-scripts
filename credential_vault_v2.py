```python
"""
Credential Vault for Network Devices
=====================================
Securely store and retrieve SSH credentials for network devices using
Fernet symmetric encryption. Credentials are encrypted at rest in a
local vault file protected by a master password.

Usage:
    # Add a device credential
    python credential_vault.py add --device 192.168.1.1 --username admin

    # Retrieve and use credentials (connects to device)
    python credential_vault.py connect --device 192.168.1.1 --command "show version"

    # List stored devices
    python credential_vault.py list

    # Remove a device entry
    python credential_vault.py remove --device 192.168.1.1

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
import time

import paramiko
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

DEFAULT_VAULT_FILE = os.path.expanduser("~/.net_credential_vault")
SALT_SIZE = 16
PBKDF2_ITERATIONS = 390000


def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def load_vault(vault_path: str, master_password: str) -> dict:
    if not os.path.exists(vault_path):
        return {}
    with open(vault_path, "rb") as f:
        data = f.read()
    salt = data[:SALT_SIZE]
    ciphertext = data[SALT_SIZE:]
    key = _derive_key(master_password, salt)
    try:
        plaintext = Fernet(key).decrypt(ciphertext)
    except InvalidToken:
        log.error("Invalid master password or corrupted vault.")
        sys.exit(1)
    return json.loads(plaintext.decode())


def save_vault(vault_path: str, master_password: str, vault: dict) -> None:
    salt = os.urandom(SALT_SIZE)
    key = _derive_key(master_password, salt)
    ciphertext = Fernet(key).encrypt(json.dumps(vault).encode())
    with open(vault_path, "wb") as f:
        f.write(salt + ciphertext)
    os.chmod(vault_path, 0o600)


def cmd_add(args):
    master_password = getpass.getpass("Master password: ")
    vault = load_vault(args.vault, master_password)
    username = args.username or input("Username: ")
    password = getpass.getpass(f"SSH password for {username}@{args.device}: ")
    vault[args.device] = {"username": username, "password": password, "port": args.port}
    save_vault(args.vault, master_password, vault)
    log.info("Credentials stored for %s", args.device)


def cmd_list(args):
    master_password = getpass.getpass("Master password: ")
    vault = load_vault(args.vault, master_password)
    if not vault:
        print("Vault is empty.")
        return
    print(f"{'Device':<25} {'Username':<20} {'Port'}")
    print("-" * 55)
    for device, creds in sorted(vault.items()):
        print(f"{device:<25} {creds['username']:<20} {creds.get('port', 22)}")


def cmd_remove(args):
    master_password = getpass.getpass("Master password: ")
    vault = load_vault(args.vault, master_password)
    if args.device not in vault:
        log.error("Device %s not found in vault.", args.device)
        sys.exit(1)
    del vault[args.device]
    save_vault(args.vault, master_password, vault)
    log.info("Removed credentials for %s", args.device)


def cmd_connect(args):
    master_password = getpass.getpass("Master password: ")
    vault = load_vault(args.vault, master_password)
    if args.device not in vault:
        log.error("No credentials found for %s. Run 'add' first.", args.device)
        sys.exit(1)

    creds = vault[args.device]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log.info("Connecting to %s:%s as %s", args.device, creds["port"], creds["username"])
        client.connect(
            hostname=args.device,
            port=int(creds.get("port", 22)),
            username=creds["username"],
            password=creds["password"],
            timeout=args.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        channel = client.invoke_shell()
        time.sleep(1)
        channel.recv(65535)  # flush banner

        commands = args.command if args.command else [input("Command: ")]
        for command in commands:
            log.info("Running: %s", command)
            channel.send(command + "\n")
            time.sleep(args.delay)
            output = b""
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                if channel.recv_ready():
                    chunk = channel.recv(65535)
                    output += chunk
                    if not channel.recv_ready():
                        break
                else:
                    time.sleep(0.1)
            print(output.decode(errors="replace"))

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s. Update credentials with 'add'.", args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)
    finally:
        client.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypted credential vault for network devices",
    )
    parser.add_argument(
        "--vault",
        default=DEFAULT_VAULT_FILE,
        help=f"Path to vault file (default: {DEFAULT_VAULT_FILE})",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    add_p = sub.add_parser("add", help="Store credentials for a device")
    add_p.add_argument("--device", required=True, help="Device hostname or IP")
    add_p.add_argument("--username", help="SSH username (prompted if omitted)")
    add_p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

    sub.add_parser("list", help="List devices with stored credentials")

    rm_p = sub.add_parser("remove", help="Delete credentials for a device")
    rm_p.add_argument("--device", required=True, help="Device hostname or IP")

    conn_p = sub.add_parser("connect", help="Connect to a device using stored credentials")
    conn_p.add_argument("--device", required=True, help="Device hostname or IP")
    conn_p.add_argument(
        "--command",
        nargs="+",
        metavar="CMD",
        help="Command(s) to run (interactive prompt if omitted)",
    )
    conn_p.add_argument("--timeout", type=float, default=15.0, help="Connection/read timeout seconds")
    conn_p.add_argument("--delay", type=float, default=1.5, help="Seconds to wait after sending each command")

    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "add": cmd_add,
        "list": cmd_list,
        "remove": cmd_remove,
        "connect": cmd_connect,
    }
    dispatch[args.subcommand](args)
```