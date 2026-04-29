```python
#!/usr/bin/env python3
"""
Encrypted Network Device Credential Vault Manager

Securely stores and manages SSH credentials for network devices using AES-256
encryption. Provides CLI interface to add, list, retrieve, delete, and test
credentials against live devices using paramiko.

Usage:
    python credential_vault_manager.py add --device router1 --host 10.0.1.1 \\
        --username admin --password secret123
    python credential_vault_manager.py list
    python credential_vault_manager.py get --device router1
    python credential_vault_manager.py test --device router1
    python credential_vault_manager.py delete --device router1

Prerequisites:
    pip install paramiko cryptography

The vault is stored encrypted at ./credentials.vault (binary format).
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import paramiko
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class CredentialVault:
    """Manages encrypted network device credentials."""

    def __init__(self, vault_path="credentials.vault", password="default"):
        self.vault_path = Path(vault_path)
        self.cipher = self._derive_cipher(password)
        self.credentials = self._load_vault()

    def _derive_cipher(self, password):
        """Derive Fernet cipher from master password."""
        salt = b"netauto_vault_salt"
        kdf = PBKDF2(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
        )
        key = kdf.derive(password.encode())
        return Fernet(Fernet.generate_key().replace(Fernet.generate_key()[:32], key[:32] + b"=" * 2))

    def _derive_cipher(self, password):
        """Derive Fernet cipher from master password using PBKDF2."""
        import base64

        salt = b"netauto_vault_salt"
        kdf = PBKDF2(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
        )
        key = kdf.derive(password.encode())
        key_b64 = base64.urlsafe_b64encode(key)
        return Fernet(key_b64)

    def _load_vault(self):
        """Load and decrypt credentials from vault file."""
        if not self.vault_path.exists():
            return {}
        try:
            encrypted = self.vault_path.read_bytes()
            decrypted = self.cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except Exception as e:
            logger.error(f"Failed to decrypt vault: {e}")
            return {}

    def _save_vault(self):
        """Encrypt and save credentials to vault file."""
        try:
            plaintext = json.dumps(self.credentials, indent=2).encode()
            encrypted = self.cipher.encrypt(plaintext)
            self.vault_path.write_bytes(encrypted)
            logger.info(f"Vault saved to {self.vault_path}")
        except Exception as e:
            logger.error(f"Failed to save vault: {e}")

    def add_credential(self, device, host, username, password, port=22):
        """Add or update device credential."""
        self.credentials[device] = {
            "host": host,
            "username": username,
            "password": password,
            "port": port,
        }
        self._save_vault()
        logger.info(f"Credential added for device '{device}'")

    def get_credential(self, device):
        """Retrieve credential for a device."""
        if device not in self.credentials:
            logger.error(f"Device '{device}' not found in vault")
            return None
        return self.credentials[device]

    def list_devices(self):
        """List all devices in vault (without passwords)."""
        if not self.credentials:
            logger.info("Vault is empty")
            return
        for device, cred in self.credentials.items():
            print(f"  {device}: {cred['username']}@{cred['host']}:{cred['port']}")

    def delete_credential(self, device):
        """Delete credential for a device."""
        if device in self.credentials:
            del self.credentials[device]
            self._save_vault()
            logger.info(f"Credential deleted for device '{device}'")
        else:
            logger.error(f"Device '{device}' not found")

    def test_credential(self, device, timeout=5):
        """Test SSH connectivity with stored credential."""
        cred = self.get_credential(device)
        if not cred:
            return False

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(
                hostname=cred["host"],
                port=cred["port"],
                username=cred["username"],
                password=cred["password"],
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            ssh.exec_command("show version")
            ssh.close()
            logger.info(f"✓ Connection successful for '{device}'")
            return True
        except paramiko.AuthenticationException:
            logger.error(f"✗ Authentication failed for '{device}'")
            return False
        except paramiko.SSHException as e:
            logger.error(f"✗ SSH error for '{device}': {e}")
            return False
        except Exception as e:
            logger.error(f"✗ Connection failed for '{device}': {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vault-password",
        default="default",
        help="Master password for vault (default: 'default')",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    add_parser = subparsers.add_parser("add", help="Add device credential")
    add_parser.add_argument("--device", required=True, help="Device name")
    add_parser.add_argument("--host", required=True, help="Host IP or FQDN")
    add_parser.add_argument("--username", required=True, help="SSH username")
    add_parser.add_argument("--password", required=True, help="SSH password")
    add_parser.add_argument("--port", type=int, default=22, help="SSH port")

    get_parser = subparsers.add_parser("get", help="Retrieve device credential")
    get_parser.add_argument("--device", required=True, help="Device name")

    list_parser = subparsers.add_parser("list", help="List all devices")

    delete_parser = subparsers.add_parser("delete", help="Delete device credential")
    delete_parser.add_argument("--device", required=True, help="Device name")

    test_parser = subparsers.add_parser("test", help="Test device connectivity")
    test_parser.add_argument("--device", required=True, help="Device name")
    test_parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    vault = CredentialVault(password=args.vault_password)

    if args.command == "add":
        vault.add_credential(
            args.device, args.host, args.username, args.password, args.port
        )
    elif args.command == "get":
        cred = vault.get_credential(args.device)
        if cred:
            print(json.dumps(cred, indent=2))
    elif args.command == "list":
        vault.list_devices()
    elif args.command == "delete":
        vault.delete_credential(args.device)
    elif args.command == "test":
        vault.test_credential(args.device, args.timeout)


if __name__ == "__main__":
    main()
```