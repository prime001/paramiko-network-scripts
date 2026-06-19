```python
"""
config_backup_rotate.py - Network device configuration backup with rotation and deduplication.

Purpose:
    Connects to a Cisco IOS/IOS-XE/NX-OS device via SSH, retrieves the running
    configuration, and saves it to disk. Skips writing when the config is identical
    to the most recent backup (SHA-256 deduplication). Automatically rotates old
    backups, keeping only the N most recent files per device.

Usage:
    python config_backup_rotate.py -H 192.168.1.1 -u admin -p secret
    python config_backup_rotate.py -H 10.0.0.1 -u admin --ask-pass \\
        --output-dir /backups/routers --keep 7 --device-type nxos --force

Prerequisites:
    pip install paramiko
    SSH access with privilege level 15 (or equivalent) to run 'show running-config'.
"""

import argparse
import getpass
import hashlib
import logging
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SHOW_RUN_CMD = {
    "ios": "show running-config",
    "nxos": "show running-config",
    "eos": "show running-config",
}

_PROMPT = re.compile(r"[>#]\s*$", re.MULTILINE)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _recv_until_prompt(channel: paramiko.Channel, timeout: int) -> str:
    channel.settimeout(timeout)
    buf = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = channel.recv(4096).decode("utf-8", errors="replace")
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
        if _PROMPT.search(buf):
            break
    return buf


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return client


def fetch_running_config(
    client: paramiko.SSHClient, device_type: str, timeout: int
) -> str:
    command = SHOW_RUN_CMD.get(device_type, "show running-config")
    shell = client.invoke_shell(width=512, height=5000)
    _recv_until_prompt(shell, timeout)

    shell.send("terminal length 0\n")
    _recv_until_prompt(shell, timeout)

    shell.send(f"{command}\n")
    raw = _recv_until_prompt(shell, timeout)
    shell.close()

    lines = raw.splitlines()
    start = next((i for i, ln in enumerate(lines) if command in ln), 0)
    config_lines = lines[start + 1:]
    while config_lines and _PROMPT.match(config_lines[-1].strip()):
        config_lines.pop()
    return "\n".join(config_lines).strip()


def last_backup_hash(output_dir: Path, host: str) -> Optional[str]:
    backups = sorted(output_dir.glob(f"{host}_*.cfg"), reverse=True)
    if not backups:
        return None
    try:
        return _sha256(backups[0].read_text())
    except OSError:
        return None


def rotate_backups(output_dir: Path, host: str, keep: int) -> None:
    backups = sorted(output_dir.glob(f"{host}_*.cfg"), reverse=True)
    for old in backups[keep:]:
        old.unlink()
        logger.debug("Removed old backup: %s", old.name)


def save_backup(output_dir: Path, host: str, config: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"{host}_{timestamp}.cfg"
    path.write_text(config)
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Back up a network device running-config with deduplication and rotation.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument(
        "--device-type",
        choices=list(SHOW_RUN_CMD.keys()),
        default="ios",
        help="Device OS type",
    )
    parser.add_argument("--output-dir", default="./backups", help="Backup storage directory")
    parser.add_argument("--keep", type=int, default=5, help="Backups to retain per device")
    parser.add_argument("--timeout", type=int, default=30, help="Command timeout in seconds")
    parser.add_argument(
        "--force", action="store_true", help="Save even if config is unchanged"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or password is None:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = connect(args.host, args.port, args.username, password)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except Exception as exc:
        logger.error("Connection error: %s", exc)
        return 1

    try:
        logger.info("Fetching running-config (%s)", args.device_type)
        config = fetch_running_config(client, args.device_type, args.timeout)
    except Exception as exc:
        logger.error("Failed to retrieve config: %s", exc)
        return 1
    finally:
        client.close()

    if not config:
        logger.error("Received empty configuration — aborting")
        return 1

    current_hash = _sha256(config)
    prior_hash = last_backup_hash(output_dir, args.host)

    if prior_hash and prior_hash == current_hash and not args.force:
        logger.info("Config unchanged since last backup — skipping (use --force to override)")
        return 0

    saved = save_backup(output_dir, args.host, config)
    logger.info("Backup saved: %s (%d bytes)", saved.name, saved.stat().st_size)

    rotate_backups(output_dir, args.host, args.keep)
    logger.info("Rotation complete — keeping %d backup(s) for %s", args.keep, args.host)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```