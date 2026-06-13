```python
"""
config_backup_v3.py - Incremental network device config backup with change detection.

Purpose:
    Connects to network devices via SSH and saves their running configuration,
    but only writes a new backup file when the configuration has actually changed
    (detected via SHA-256 hash comparison against the most recent backup).
    Maintains a configurable number of timestamped backups per device with
    automatic rotation of oldest files.

Usage:
    # Single device, prompt for password
    python config_backup_v3.py -d 192.168.1.1 -u admin

    # Single device with inline password
    python config_backup_v3.py -d 192.168.1.1 -u admin -p secret

    # Multiple devices from file (one IP/hostname per line, # comments allowed)
    python config_backup_v3.py -D devices.txt -u admin --password-env NET_PASS

    # Custom output dir, keep last 10 backups per device
    python config_backup_v3.py -d 192.168.1.1 -u admin -p secret \
        -o /var/backups/network --keep 10

Prerequisites:
    pip install paramiko
    SSH access with a user able to run 'show running-config' (or OS equivalent).
"""

import argparse
import getpass
import hashlib
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

SHOW_CONFIG_CMD = {
    "ios": "show running-config",
    "nxos": "show running-config",
    "eos": "show running-config",
    "junos": "show configuration",
    "default": "show running-config",
}


def connect(host, username, password, port, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def fetch_config(client, command, timeout):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        logger.debug("stderr from device: %s", err)
    return output


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def latest_backup(backup_dir, host):
    """Return (path, hash) of the most recent backup for host, or (None, None)."""
    files = sorted(backup_dir.glob(f"{host}_*.cfg"))
    if not files:
        return None, None
    content = files[-1].read_text(encoding="utf-8", errors="replace")
    return files[-1], sha256(content)


def rotate(backup_dir, host, keep):
    files = sorted(backup_dir.glob(f"{host}_*.cfg"))
    for old in files[: max(0, len(files) - keep)]:
        old.unlink()
        logger.debug("Removed old backup: %s", old.name)


def backup_device(host, username, password, backup_dir, port, keep, os_type, timeout):
    command = SHOW_CONFIG_CMD.get(os_type, SHOW_CONFIG_CMD["default"])
    logger.info("[%s] Connecting...", host)

    try:
        client = connect(host, username, password, port, timeout)
    except paramiko.AuthenticationException:
        logger.error("[%s] Authentication failed", host)
        return False
    except (paramiko.SSHException, OSError) as exc:
        logger.error("[%s] Connection error: %s", host, exc)
        return False

    try:
        config = fetch_config(client, command, timeout)
    except Exception as exc:
        logger.error("[%s] Failed to retrieve config: %s", host, exc)
        return False
    finally:
        client.close()

    if not config.strip():
        logger.warning("[%s] Empty config returned — skipping", host)
        return False

    new_hash = sha256(config)
    _latest_path, latest_hash = latest_backup(backup_dir, host)

    if latest_hash == new_hash:
        logger.info("[%s] No change detected — skipping write", host)
        return True

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = backup_dir / f"{host}_{timestamp}.cfg"
    out_path.write_text(config, encoding="utf-8")
    logger.info("[%s] Saved %s", host, out_path.name)

    rotate(backup_dir, host, keep)
    return True


def parse_args():
    parser = argparse.ArgumentParser(
        description="Incremental config backup — only writes when config has changed."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("-D", "--device-file", help="File listing one device per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (omit to prompt)")
    parser.add_argument(
        "--password-env",
        metavar="VAR",
        help="Read password from this environment variable",
    )
    parser.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "-o", "--output-dir",
        default="./backups",
        help="Backup directory (default: ./backups)",
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=5,
        help="Max backups to retain per device (default: 5)",
    )
    parser.add_argument(
        "--os-type",
        choices=list(SHOW_CONFIG_CMD.keys()),
        default="default",
        help="Device OS — controls which show command is used",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="SSH connection/command timeout in seconds (default: 30)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.password_env:
        password = os.environ.get(args.password_env)
        if not password:
            logger.error("Environment variable '%s' is not set or empty", args.password_env)
            sys.exit(1)
    elif args.password:
        password = args.password
    else:
        password = getpass.getpass(f"Password for {args.username}: ")

    backup_dir = Path(args.output_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    if args.device:
        devices = [args.device.strip()]
    else:
        device_path = Path(args.device_file)
        if not device_path.exists():
            logger.error("Device file not found: %s", args.device_file)
            sys.exit(1)
        devices = [
            line.strip()
            for line in device_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    if not devices:
        logger.error("No devices to process")
        sys.exit(1)

    succeeded = sum(
        backup_device(
            host=h,
            username=args.username,
            password=password,
            backup_dir=backup_dir,
            port=args.port,
            keep=args.keep,
            os_type=args.os_type,
            timeout=args.timeout,
        )
        for h in devices
    )
    failed = len(devices) - succeeded
    logger.info("Complete: %d/%d devices succeeded", succeeded, len(devices))

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
```