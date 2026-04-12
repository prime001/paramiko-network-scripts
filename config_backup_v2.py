```python
"""
017_config_backup_rotate.py - Rotating Compressed Configuration Backup Tool

Purpose:
    Connects to network devices via SSH using Paramiko, retrieves running
    configurations, and stores them as compressed backups with automatic
    rotation. Supports retention policies to prune old backups.

Usage:
    Single device:
        python 017_config_backup_rotate.py -H 192.168.1.1 -u admin -p secret

    Inventory file (one IP per line):
        python 017_config_backup_rotate.py -i inventory.txt -u admin -p secret

    Custom backup directory and retention:
        python 017_config_backup_rotate.py -H 192.168.1.1 -u admin \
            -d /opt/backups --retain 30

Prerequisites:
    pip install paramiko
    SSH access to target devices
    Devices must support 'show running-config' or equivalent
"""

import argparse
import gzip
import logging
import os
import shutil
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

BACKUP_COMMANDS = [
    "show running-config",
    "show run",
    "display current-configuration",
]

CONNECT_TIMEOUT = 15
RECV_TIMEOUT = 30
BUFFER_SIZE = 65535


def ssh_get_config(host: str, username: str, password: str, port: int = 22) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell(width=256, height=256)
        time.sleep(1)
        shell.recv(BUFFER_SIZE)  # drain banner/prompt

        output = ""
        for cmd in BACKUP_COMMANDS:
            shell.send(cmd + "\n")
            time.sleep(RECV_TIMEOUT * 0.1)
            deadline = time.time() + RECV_TIMEOUT
            buf = ""
            while time.time() < deadline:
                if shell.recv_ready():
                    buf += shell.recv(BUFFER_SIZE).decode("utf-8", errors="replace")
                    if buf.rstrip().endswith(("#", ">", "$")):
                        break
                else:
                    time.sleep(0.3)
            if len(buf) > 200:
                output = buf
                break

        if not output:
            raise RuntimeError(f"No config output received from {host}")
        return output
    finally:
        client.close()


def write_compressed_backup(host: str, config: str, backup_dir: Path) -> Path:
    device_dir = backup_dir / host
    device_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = device_dir / f"{host}_{timestamp}.cfg.gz"
    with gzip.open(filename, "wt", encoding="utf-8") as fh:
        fh.write(config)
    log.info("Saved backup: %s (%d bytes compressed)", filename, filename.stat().st_size)
    return filename


def rotate_backups(host: str, backup_dir: Path, retain_days: int) -> int:
    device_dir = backup_dir / host
    if not device_dir.exists():
        return 0
    cutoff = datetime.now() - timedelta(days=retain_days)
    removed = 0
    for f in sorted(device_dir.glob("*.cfg.gz")):
        mtime = datetime.fromtimestamp(f.stat().st_mtime)
        if mtime < cutoff:
            f.unlink()
            log.debug("Pruned old backup: %s", f)
            removed += 1
    return removed


def backup_device(
    host: str,
    username: str,
    password: str,
    port: int,
    backup_dir: Path,
    retain_days: int,
) -> bool:
    log.info("Connecting to %s:%d", host, port)
    try:
        config = ssh_get_config(host, username, password, port)
        write_compressed_backup(host, config, backup_dir)
        pruned = rotate_backups(host, backup_dir, retain_days)
        if pruned:
            log.info("Pruned %d expired backup(s) for %s", pruned, host)
        return True
    except paramiko.AuthenticationException:
        log.error("[%s] Authentication failed", host)
    except paramiko.SSHException as exc:
        log.error("[%s] SSH error: %s", host, exc)
    except OSError as exc:
        log.error("[%s] Connection error: %s", host, exc)
    except RuntimeError as exc:
        log.error("[%s] %s", host, exc)
    return False


def load_inventory(path: str) -> list[str]:
    hosts = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rotating compressed config backup for network devices",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-H", "--host", help="Single device IP or hostname")
    target.add_argument("-i", "--inventory", help="File with one device per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("-d", "--backup-dir", default="./backups", help="Root backup directory")
    parser.add_argument("--retain", type=int, default=14, metavar="DAYS",
                        help="Days of backups to retain per device")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.password is None:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}: ")

    hosts = [args.host] if args.host else load_inventory(args.inventory)
    if not hosts:
        log.error("No hosts to process.")
        sys.exit(1)

    backup_dir = Path(args.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    results = {"ok": 0, "fail": 0}
    for host in hosts:
        success = backup_device(
            host=host,
            username=args.username,
            password=args.password,
            port=args.port,
            backup_dir=backup_dir,
            retain_days=args.retain,
        )
        if success:
            results["ok"] += 1
        else:
            results["fail"] += 1

    log.info("Done. Success: %d  Failed: %d", results["ok"], results["fail"])
    sys.exit(0 if results["fail"] == 0 else 1)
```