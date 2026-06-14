sftp_file_transfer.py - Transfer files to/from network devices via SFTP.

Purpose:
    Uses paramiko's SFTP subsystem to upload or download files on network
    devices that expose an SFTP server (Cisco IOS-XE, NX-OS, EOS, Junos).
    Useful for pushing configuration files, pulling crash logs, certificates,
    or core dumps without relying on TFTP/SCP external servers.

Usage:
    # Upload a file to a device
    python sftp_file_transfer.py --host 192.168.1.1 --user admin \
        --password secret --upload local.cfg flash:/backup.cfg

    # Download a file from a device
    python sftp_file_transfer.py --host 192.168.1.1 --user admin \
        --password secret --download flash:/running-config.txt ./pulled.cfg

    # Use SSH key auth and custom port
    python sftp_file_transfer.py --host 192.168.1.1 --user admin \
        --key ~/.ssh/id_rsa --port 22 --download bootflash:/crashinfo ./crash.log

Prerequisites:
    pip install paramiko
    SFTP must be enabled on the target device:
      Cisco IOS-XE: ip ssh server algorithm mac hmac-sha2-256
      NX-OS:        feature sftp-server
      EOS:          management ssh / sftp-server enable
"""

import argparse
import logging
import os
import sys
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def build_ssh_client(host: str, port: int, username: str,
                     password: str | None, key_path: str | None,
                     timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "allow_agent": False,
        "look_for_keys": False,
    }

    if key_path:
        connect_kwargs["key_filename"] = os.path.expanduser(key_path)
        connect_kwargs["look_for_keys"] = False
    elif password:
        connect_kwargs["password"] = password
    else:
        log.error("Provide --password or --key")
        sys.exit(1)

    try:
        client.connect(**connect_kwargs)
        log.info("SSH connected to %s:%d", host, port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH negotiation failed: %s", exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    return client


def upload_file(sftp: paramiko.SFTPClient, local_path: str,
                remote_path: str) -> None:
    local = Path(local_path)
    if not local.exists():
        log.error("Local file not found: %s", local_path)
        sys.exit(1)

    size = local.stat().st_size
    log.info("Uploading %s (%d bytes) -> %s", local_path, size, remote_path)

    transferred: list[int] = [0]

    def _progress(sent: int, total: int) -> None:
        pct = int(sent / total * 100)
        if pct != transferred[0]:
            log.debug("  %d%%  (%d / %d bytes)", pct, sent, total)
            transferred[0] = pct

    try:
        sftp.put(local_path, remote_path, callback=_progress)
        log.info("Upload complete: %s", remote_path)
    except OSError as exc:
        log.error("Upload failed: %s", exc)
        sys.exit(1)


def download_file(sftp: paramiko.SFTPClient, remote_path: str,
                  local_path: str) -> None:
    log.info("Downloading %s -> %s", remote_path, local_path)

    try:
        remote_stat = sftp.stat(remote_path)
        size = remote_stat.st_size
        log.info("Remote file size: %d bytes", size)
    except OSError as exc:
        log.error("Cannot stat remote path %s: %s", remote_path, exc)
        sys.exit(1)

    transferred: list[int] = [0]

    def _progress(sent: int, total: int) -> None:
        pct = int(sent / total * 100)
        if pct != transferred[0]:
            log.debug("  %d%%  (%d / %d bytes)", pct, sent, total)
            transferred[0] = pct

    try:
        sftp.get(remote_path, local_path, callback=_progress)
        actual = Path(local_path).stat().st_size
        log.info("Download complete: %s (%d bytes)", local_path, actual)
    except OSError as exc:
        log.error("Download failed: %s", exc)
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transfer files to/from network devices via SFTP"
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument("--user", required=True, help="SSH username")

    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--password", help="SSH password")
    auth.add_argument("--key", metavar="KEY_FILE", help="Path to SSH private key")

    direction = parser.add_mutually_exclusive_group(required=True)
    direction.add_argument(
        "--upload",
        nargs=2,
        metavar=("LOCAL", "REMOTE"),
        help="Upload LOCAL file to REMOTE path on device",
    )
    direction.add_argument(
        "--download",
        nargs=2,
        metavar=("REMOTE", "LOCAL"),
        help="Download REMOTE path from device to LOCAL file",
    )

    parser.add_argument(
        "--timeout", type=int, default=30, help="Connection timeout in seconds"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    client = build_ssh_client(
        host=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        key_path=args.key,
        timeout=args.timeout,
    )

    try:
        sftp = client.open_sftp()
        log.info("SFTP session opened")

        if args.upload:
            local_src, remote_dst = args.upload
            upload_file(sftp, local_src, remote_dst)
        else:
            remote_src, local_dst = args.download
            download_file(sftp, remote_src, local_dst)

    except paramiko.SSHException as exc:
        log.error("SFTP session error: %s", exc)
        sys.exit(1)
    finally:
        try:
            sftp.close()
        except Exception:
            pass
        client.close()
        log.info("Connection closed")