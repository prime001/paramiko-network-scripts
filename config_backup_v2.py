```python
"""
config_backup_rotate.py - Rotating Configuration Backup with Integrity Verification

Purpose:
    Connects to network devices via SSH, retrieves running configurations,
    saves them with timestamps, verifies integrity via SHA-256 checksums,
    and rotates old backups to keep storage bounded.

Usage:
    # Single device
    python config_backup_rotate.py -d 192.168.1.1 -u admin -p secret

    # Multiple devices from file (one IP per line)
    python config_backup_rotate.py -f devices.txt -u admin -p secret --keep 10

    # Custom backup directory and output format
    python config_backup_rotate.py -d 10.0.0.1 -u admin --backup-dir /mnt/backups --keep 5

Prerequisites:
    pip install paramiko
    SSH access to target devices (Cisco IOS/IOS-XE/NX-OS compatible)
"""

import argparse
import getpass
import hashlib
import logging
import os
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

BACKUP_COMMANDS = [
    "terminal length 0",
    "show running-config",
]


def ssh_get_config(host: str, username: str, password: str, timeout: int = 30) -> str:
    """Open SSH session and retrieve running configuration."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell(width=250, height=5000)
        time.sleep(1)
        shell.recv(65535)  # flush banner

        output_parts = []
        for cmd in BACKUP_COMMANDS:
            shell.send(cmd + "\n")
            time.sleep(2)
            chunk = b""
            while shell.recv_ready():
                chunk += shell.recv(65535)
                time.sleep(0.2)
            output_parts.append(chunk.decode("utf-8", errors="replace"))

        full_output = "\n".join(output_parts)
        # Strip ANSI escape sequences and terminal control chars
        clean = re.sub(r"\x1b\[[0-9;]*[mGKHF]", "", full_output)
        return clean
    finally:
        client.close()


def sha256_of_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def save_backup(host: str, config_text: str, backup_dir: Path) -> Path:
    """Write config to a timestamped file; return the file path."""
    safe_host = host.replace(".", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_host}_{timestamp}.cfg"
    device_dir = backup_dir / safe_host
    device_dir.mkdir(parents=True, exist_ok=True)

    filepath = device_dir / filename
    filepath.write_text(config_text, encoding="utf-8")

    checksum = sha256_of_string(config_text)
    checksum_file = filepath.with_suffix(".sha256")
    checksum_file.write_text(f"{checksum}  {filename}\n", encoding="utf-8")

    log.info("Saved: %s (SHA-256: %s...)", filepath, checksum[:16])
    return filepath


def rotate_backups(host: str, backup_dir: Path, keep: int) -> int:
    """Remove oldest backups beyond the keep limit. Returns count removed."""
    safe_host = host.replace(".", "_").replace(":", "_")
    device_dir = backup_dir / safe_host
    if not device_dir.exists():
        return 0

    cfg_files = sorted(device_dir.glob("*.cfg"), key=lambda p: p.stat().st_mtime)
    to_remove = cfg_files[: max(0, len(cfg_files) - keep)]
    for old_file in to_remove:
        old_file.unlink(missing_ok=True)
        old_file.with_suffix(".sha256").unlink(missing_ok=True)
        log.debug("Rotated old backup: %s", old_file.name)

    return len(to_remove)


def verify_backup(filepath: Path) -> bool:
    """Re-read saved file and confirm checksum matches."""
    checksum_file = filepath.with_suffix(".sha256")
    if not checksum_file.exists():
        log.warning("No checksum file for %s — skipping verification", filepath.name)
        return False
    stored = checksum_file.read_text().split()[0]
    actual = sha256_of_string(filepath.read_text(encoding="utf-8"))
    if stored != actual:
        log.error("INTEGRITY FAILURE for %s", filepath.name)
        return False
    return True


def backup_device(
    host: str, username: str, password: str, backup_dir: Path, keep: int, timeout: int
) -> dict:
    result = {"host": host, "success": False, "path": None, "rotated": 0, "error": None}
    try:
        socket.setdefaulttimeout(timeout)
        log.info("Connecting to %s ...", host)
        config_text = ssh_get_config(host, username, password, timeout)

        if len(config_text.strip()) < 50:
            raise ValueError("Retrieved config appears empty or truncated")

        filepath = save_backup(host, config_text, backup_dir)
        if not verify_backup(filepath):
            raise IOError("Post-write integrity check failed")

        rotated = rotate_backups(host, backup_dir, keep)
        result.update(success=True, path=str(filepath), rotated=rotated)
        log.info("Backup complete for %s (rotated %d old)", host, rotated)
    except (paramiko.AuthenticationException, paramiko.SSHException) as exc:
        result["error"] = f"SSH error: {exc}"
        log.error("SSH failure for %s: %s", host, exc)
    except (socket.timeout, socket.error) as exc:
        result["error"] = f"Network error: {exc}"
        log.error("Network failure for %s: %s", host, exc)
    except Exception as exc:
        result["error"] = str(exc)
        log.error("Unexpected error for %s: %s", host, exc)
    return result


def parse_args():
    parser = argparse.ArgumentParser(
        description="Rotating network config backup with integrity verification"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("-f", "--file", help="File with one device per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--backup-dir",
        default="./backups",
        help="Root backup directory (default: ./backups)",
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=7,
        help="Number of backups to retain per device (default: 7)",
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="SSH connection timeout in seconds"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    if args.device:
        devices = [args.device.strip()]
    else:
        device_file = Path(args.file)
        if not device_file.exists():
            log.error("Device file not found: %s", args.file)
            sys.exit(1)
        devices = [
            line.strip()
            for line in device_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    backup_dir = Path(args.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for host in devices:
        r = backup_device(host, args.username, password, backup_dir, args.keep, args.timeout)
        results.append(r)

    passed = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]

    print(f"\n--- Backup Summary ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---")
    print(f"  Devices processed : {len(results)}")
    print(f"  Succeeded         : {len(passed)}")
    print(f"  Failed            : {len(failed)}")
    if failed:
        print("\nFailed devices:")
        for r in failed:
            print(f"  {r['host']}: {r['error']}")

    sys.exit(0 if not failed else 1)
```