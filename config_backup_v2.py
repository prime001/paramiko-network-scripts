config_backup_rotate.py - Network device configuration backup with rotation and change detection.

Purpose:
    Connects to a network device via SSH, retrieves the running configuration,
    and saves it locally with timestamped filenames. Skips the backup if the
    configuration is unchanged since the last run (MD5 comparison). Supports
    gzip compression and enforces a per-device retention limit by removing the
    oldest files. A JSON manifest tracks backup history and last-known hashes.

Usage:
    python config_backup_rotate.py -d 192.168.1.1 -u admin -p secret
    python config_backup_rotate.py -d 192.168.1.1 -u admin -p secret --keep 10 --compress
    python config_backup_rotate.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa --backup-dir /backups
    python config_backup_rotate.py -d 192.168.1.1 -u admin -p secret --force --verbose

Prerequisites:
    - pip install paramiko
    - SSH access to the target device (Cisco IOS, NX-OS, or compatible CLI)
    - terminal length 0 (or equivalent) supported by the device
    - Write permissions to the backup directory
"""

import argparse
import gzip
import hashlib
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

MANIFEST_FILE = "backup_manifest.json"


def load_manifest(backup_dir: Path) -> dict:
    path = backup_dir / MANIFEST_FILE
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def save_manifest(backup_dir: Path, manifest: dict) -> None:
    with open(backup_dir / MANIFEST_FILE, "w") as f:
        json.dump(manifest, f, indent=2)


def fetch_running_config(
    host: str, port: int, username: str, password: str | None,
    key_file: str | None, timeout: int
) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password

    try:
        client.connect(**kwargs)
        shell = client.invoke_shell(width=300, height=1000)
        time.sleep(1)
        shell.recv(65535)  # drain login banner

        shell.send("terminal length 0\n")
        time.sleep(0.5)
        shell.recv(65535)

        shell.send("show running-config\n")
        time.sleep(4)

        chunks = []
        while shell.recv_ready():
            chunks.append(shell.recv(65535).decode("utf-8", errors="replace"))
            time.sleep(0.3)

        return "".join(chunks)
    finally:
        client.close()


def rotate_backups(backup_dir: Path, device_key: str, keep: int, manifest: dict) -> None:
    entries = manifest.get(device_key, {}).get("backups", [])
    while len(entries) > keep:
        oldest = entries.pop(0)
        old_path = backup_dir / oldest["filename"]
        if old_path.exists():
            old_path.unlink()
            logger.info("Rotated old backup: %s", oldest["filename"])


def write_backup(backup_dir: Path, device_key: str, config: str, compress: bool) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = ".cfg.gz" if compress else ".cfg"
    filename = f"{device_key}_{timestamp}{ext}"
    filepath = backup_dir / filename
    if compress:
        with gzip.open(filepath, "wt", encoding="utf-8") as f:
            f.write(config)
    else:
        filepath.write_text(config, encoding="utf-8")
    return filename


def backup_device(
    host: str, port: int, username: str, password: str | None,
    key_file: str | None, backup_dir: Path, keep: int,
    compress: bool, force: bool, timeout: int,
) -> bool:
    device_key = host.replace(".", "_").replace(":", "_")
    backup_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(backup_dir)

    logger.info("Connecting to %s:%d as %s", host, port, username)
    try:
        config = fetch_running_config(host, port, username, password, key_file, timeout)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s", host)
        return False
    except paramiko.SSHException as exc:
        logger.error("SSH error on %s: %s", host, exc)
        return False
    except OSError as exc:
        logger.error("Network error on %s: %s", host, exc)
        return False

    current_hash = hashlib.md5(config.encode()).hexdigest()
    last_hash = manifest.get(device_key, {}).get("last_hash", "")

    if not force and current_hash == last_hash:
        logger.info("Config unchanged (md5=%s) — skipping backup for %s", current_hash, host)
        return True

    filename = write_backup(backup_dir, device_key, config, compress)
    logger.info("Saved: %s", filename)

    if device_key not in manifest:
        manifest[device_key] = {"backups": []}
    manifest[device_key]["backups"].append({
        "filename": filename,
        "timestamp": datetime.now().isoformat(),
        "md5": current_hash,
    })
    manifest[device_key]["last_hash"] = current_hash

    rotate_backups(backup_dir, device_key, keep, manifest)
    save_manifest(backup_dir, manifest)
    logger.info("Done. Device=%s md5=%s retained=%d",
                host, current_hash, len(manifest[device_key]["backups"]))
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Back up network device running-config with rotation and change detection."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("-k", "--key-file", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--backup-dir", default="./backups",
        help="Directory for backup files (default: ./backups)",
    )
    parser.add_argument(
        "--keep", type=int, default=5,
        help="Max backups to retain per device (default: 5)",
    )
    parser.add_argument("--compress", action="store_true", help="Compress backups with gzip")
    parser.add_argument(
        "--force", action="store_true",
        help="Save backup even when config is unchanged",
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="SSH connection timeout in seconds (default: 30)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        logger.error("Provide --password or --key-file")
        sys.exit(1)

    ok = backup_device(
        host=args.device,
        port=args.port,
        username=args.username,
        password=args.password,
        key_file=args.key_file,
        backup_dir=Path(args.backup_dir),
        keep=args.keep,
        compress=args.compress,
        force=args.force,
        timeout=args.timeout,
    )
    sys.exit(0 if ok else 1)