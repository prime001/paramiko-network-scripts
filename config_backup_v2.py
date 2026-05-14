```python
"""
scp_config_pull.py - Pull configuration files from network device storage via SFTP.

Purpose:
    Transfers config files directly from device flash/disk using paramiko's SFTP
    client, rather than capturing 'show running-config' CLI output. Useful when
    you need the raw file from device storage (startup-config, running-config,
    IOS image manifests) with a verifiable byte-for-byte transfer.

Usage:
    python scp_config_pull.py -H 192.168.1.1 -u admin -p secret
    python scp_config_pull.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa \
        --source flash:/startup-config --dest ./backups/
    python scp_config_pull.py -H 192.168.1.1 -u admin -p secret \
        --list flash:/

Prerequisites:
    pip install paramiko

    Enable SFTP server on the device before use:
        Cisco IOS/IOS-XE:  ip ssh version 2   (SFTP built-in on 12.4+)
        Cisco NX-OS:       feature sftp-server
        Cisco ASA 9.x+:    ssh scopy enable
"""

import argparse
import getpass
import logging
import os
import socket
import stat
import sys
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def connect(host, port, username, password=None, key_path=None, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = os.path.expanduser(key_path)
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def pull_file(sftp, remote_path, local_path):
    log.info("Fetching %s", remote_path)
    sftp.get(remote_path, str(local_path))
    size = local_path.stat().st_size
    log.info("Saved %d bytes to %s", size, local_path)
    return size


def list_remote_dir(sftp, remote_dir):
    entries = sftp.listdir_attr(remote_dir)
    files = [
        (e.filename, e.st_size or 0)
        for e in entries
        if not stat.S_ISDIR(e.st_mode or 0)
    ]
    return sorted(files)


def build_dest_path(dest_dir, host, remote_path):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = Path(remote_path).name
    out = Path(dest_dir)
    out.mkdir(parents=True, exist_ok=True)
    return out / f"{host}_{name}_{ts}"


def parse_args():
    p = argparse.ArgumentParser(
        description="Pull config files from device flash/disk via SFTP"
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--key", metavar="PATH", help="SSH private key file")
    p.add_argument(
        "--source",
        default="flash:/startup-config",
        help="Remote file path (default: flash:/startup-config)",
    )
    p.add_argument(
        "--dest",
        default="./sftp_backups",
        help="Local output directory (default: ./sftp_backups)",
    )
    p.add_argument(
        "--list",
        metavar="REMOTE_DIR",
        help="List files in a remote directory instead of pulling",
    )
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if not args.key and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
        client = connect(
            args.host,
            args.port,
            args.username,
            password=args.password,
            key_path=args.key,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException as exc:
        log.error("Authentication failed: %s", exc)
        sys.exit(1)
    except (paramiko.SSHException, socket.timeout, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        sftp = client.open_sftp()

        if args.list:
            try:
                files = list_remote_dir(sftp, args.list)
            except IOError as exc:
                log.error("Cannot list %s: %s", args.list, exc)
                sys.exit(1)
            print(f"\n{'Filename':<44} {'Bytes':>12}")
            print("-" * 58)
            for name, size in files:
                print(f"{name:<44} {size:>12,}")
            print(f"\n{len(files)} file(s) listed in {args.list}")
        else:
            out = build_dest_path(args.dest, args.host, args.source)
            try:
                nbytes = pull_file(sftp, args.source, out)
            except IOError as exc:
                log.error("Transfer failed: %s", exc)
                log.error(
                    "Verify SFTP is enabled on the device and '%s' exists",
                    args.source,
                )
                sys.exit(1)
            print(f"\nBackup complete: {out} ({nbytes:,} bytes)")

        sftp.close()
    finally:
        client.close()
        log.debug("Connection closed")


if __name__ == "__main__":
    main()
```