```python
"""
config_backup_rotate.py — Rotating config backup with change detection.

Connects to a network device via SSH, retrieves the running configuration,
and saves it only when the content differs from the previous backup.
Maintains a configurable retention window and compresses archives older
than a threshold to save disk space.

Usage:
    python config_backup_rotate.py -H 192.168.1.1 -u admin -p secret
    python config_backup_rotate.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa \
        --output-dir /backups/routers --keep 30 --compress-after 7

Prerequisites:
    pip install paramiko
"""

import argparse
import gzip
import hashlib
import logging
import os
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SHOW_RUN_CMD = "show running-config"
TIMESTAMP_FMT = "%Y%m%d_%H%M%S"


def connect(host: str, port: int, username: str, password: str | None,
            key_path: str | None, timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def fetch_config(client: paramiko.SSHClient, command: str, recv_timeout: int) -> str:
    chan = client.get_transport().open_session()
    chan.settimeout(recv_timeout)
    chan.exec_command(command)
    stdout = chan.makefile("r")
    output = stdout.read()
    exit_status = chan.recv_exit_status()
    chan.close()
    if exit_status != 0:
        stderr = chan.makefile_stderr("r").read()
        raise RuntimeError(f"Command exited {exit_status}: {stderr.strip()}")
    return output if isinstance(output, str) else output.decode("utf-8", errors="replace")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def latest_backup(backup_dir: Path) -> Path | None:
    candidates = sorted(
        backup_dir.glob("*.cfg"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def read_backup(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


def save_backup(backup_dir: Path, host: str, config: str) -> Path:
    ts = datetime.now().strftime(TIMESTAMP_FMT)
    filename = backup_dir / f"{host}_{ts}.cfg"
    filename.write_text(config, encoding="utf-8")
    return filename


def enforce_retention(backup_dir: Path, host: str, keep: int,
                      compress_after_days: int) -> None:
    all_backups = sorted(
        list(backup_dir.glob(f"{host}_*.cfg")) +
        list(backup_dir.glob(f"{host}_*.cfg.gz")),
        key=lambda p: p.stat().st_mtime,
    )

    cutoff = datetime.now() - timedelta(days=compress_after_days)
    for path in all_backups:
        if path.suffix != ".gz" and datetime.fromtimestamp(path.stat().st_mtime) < cutoff:
            gz_path = path.with_suffix(".cfg.gz")
            with open(path, "rb") as src, gzip.open(gz_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            path.unlink()
            log.info("Compressed %s → %s", path.name, gz_path.name)

    all_backups = sorted(
        list(backup_dir.glob(f"{host}_*.cfg")) +
        list(backup_dir.glob(f"{host}_*.cfg.gz")),
        key=lambda p: p.stat().st_mtime,
    )
    excess = all_backups[: max(0, len(all_backups) - keep)]
    for path in excess:
        path.unlink()
        log.info("Pruned old backup: %s", path.name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rotating config backup with change detection."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-P", "--port", type=int, default=22, help="SSH port")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", dest="key_path", default=None,
                        help="Path to SSH private key")
    parser.add_argument("--command", default=SHOW_RUN_CMD,
                        help="Command to retrieve config")
    parser.add_argument("--output-dir", default="./backups",
                        help="Directory to store backups")
    parser.add_argument("--keep", type=int, default=14,
                        help="Number of backups to retain per device")
    parser.add_argument("--compress-after", type=int, default=3,
                        dest="compress_after",
                        help="Compress backups older than N days")
    parser.add_argument("--timeout", type=int, default=30,
                        help="SSH connection timeout in seconds")
    parser.add_argument("--recv-timeout", type=int, default=60,
                        dest="recv_timeout",
                        help="Command receive timeout in seconds")
    parser.add_argument("--force", action="store_true",
                        help="Save backup even if config is unchanged")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    if not args.password and not args.key_path:
        log.error("Provide --password or --key for authentication.")
        sys.exit(1)

    backup_dir = Path(args.output_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    try:
        log.info("Connecting to %s:%s", args.host, args.port)
        client = connect(args.host, args.port, args.username,
                         args.password, args.key_path, args.timeout)
    except (paramiko.AuthenticationException,
            paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.debug("Running: %s", args.command)
        config = fetch_config(client, args.command, args.recv_timeout)
    except (RuntimeError, paramiko.SSHException, OSError) as exc:
        log.error("Failed to retrieve config: %s", exc)
        client.close()
        sys.exit(1)
    finally:
        client.close()

    current_hash = sha256(config)
    prior = latest_backup(backup_dir)

    if prior and not args.force:
        prior_hash = sha256(read_backup(prior))
        if current_hash == prior_hash:
            log.info("Config unchanged since %s — skipping save.", prior.name)
            enforce_retention(backup_dir, args.host, args.keep, args.compress_after)
            sys.exit(0)

    saved = save_backup(backup_dir, args.host, config)
    log.info("Saved %s (%d bytes, sha256=%s…)", saved.name, len(config),
             current_hash[:12])

    enforce_retention(backup_dir, args.host, args.keep, args.compress_after)
```