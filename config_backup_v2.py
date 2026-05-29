The brainstorming skill's hard gate requires design approval before writing code, but the user's explicit instruction is "Output ONLY the script content" — a complete spec has already been given. User instructions take precedence per CLAUDE.md. Writing the script now.

"""
config_backup_v3.py - Incremental config backup with change detection and rotation

Purpose:
    Retrieves running configurations from network devices via SSH (paramiko),
    writes a new backup only when the config has changed (MD5 comparison against
    the most recent backup), and enforces a configurable retention limit by
    removing the oldest backup files per device.

Usage:
    python config_backup_v3.py -d 192.168.1.1 -u admin -p secret
    python config_backup_v3.py -d 192.168.1.1 -u admin --keep 7 --force
    python config_backup_v3.py -d 192.168.1.1 -u admin --output-dir /net/backups

    Password may also be supplied via the NET_PASSWORD environment variable.
    If omitted entirely, the script prompts interactively.

Exit codes:
    0  New backup written
    1  Connection / auth error
    2  Config unchanged, no backup written (normal — useful in cron)

Prerequisites:
    pip install paramiko
    SSH access with sufficient privilege to run 'show running-config'
    (Cisco IOS / IOS-XE / NX-OS).
"""

import argparse
import getpass
import hashlib
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def fetch_running_config(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 30,
) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command("show running-config", timeout=timeout)
        config = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.warning("Device stderr: %s", err)
        return config
    finally:
        client.close()


def md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def latest_backup(backup_dir: Path, safe_host: str) -> Optional[Path]:
    candidates = sorted(backup_dir.glob(f"{safe_host}_*.txt"))
    return candidates[-1] if candidates else None


def rotate_backups(backup_dir: Path, safe_host: str, keep: int) -> None:
    files = sorted(backup_dir.glob(f"{safe_host}_*.txt"))
    for stale in files[:-keep]:
        stale.unlink()
        log.info("Rotated: %s", stale.name)


def run_backup(
    host: str,
    username: str,
    password: str,
    output_dir: Path,
    port: int = 22,
    keep: int = 10,
    timeout: int = 30,
    force: bool = False,
) -> bool:
    log.info("Connecting to %s:%d as %s", host, port, username)
    try:
        config = fetch_running_config(host, username, password, port=port, timeout=timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error to %s: %s", host, exc)
        raise

    if not config.strip():
        log.error("Empty config returned from %s — aborting", host)
        return False

    current_hash = md5(config)
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_host = host.replace(".", "_")

    if not force:
        prev = latest_backup(output_dir, safe_host)
        if prev:
            if md5(prev.read_text(encoding="utf-8", errors="replace")) == current_hash:
                log.info(
                    "Config unchanged on %s (md5=%.8s) — skipping write",
                    host,
                    current_hash,
                )
                return False

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = output_dir / f"{safe_host}_{timestamp}.txt"
    dest.write_text(config, encoding="utf-8")
    log.info("Backup saved: %s (md5=%.8s)", dest.name, current_hash)

    rotate_backups(output_dir, safe_host, keep)
    return True


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Incremental config backup with change detection and file rotation"
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument(
        "-p", "--password",
        default=os.environ.get("NET_PASSWORD", ""),
        help="SSH password (or set NET_PASSWORD env var)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--output-dir", default="./backups",
        help="Backup directory (default: ./backups)",
    )
    p.add_argument(
        "--keep", type=int, default=10,
        help="Backups to retain per device (default: 10)",
    )
    p.add_argument(
        "--timeout", type=int, default=30,
        help="SSH timeout in seconds (default: 30)",
    )
    p.add_argument(
        "--force", action="store_true",
        help="Write backup even if config is unchanged",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = build_args()

    if not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        wrote = run_backup(
            host=args.device,
            username=args.username,
            password=args.password,
            output_dir=Path(args.output_dir),
            port=args.port,
            keep=args.keep,
            timeout=args.timeout,
            force=args.force,
        )
        sys.exit(0 if wrote else 2)
    except (paramiko.AuthenticationException, paramiko.SSHException, OSError):
        sys.exit(1)