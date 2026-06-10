password_rotation.py - Network device password rotation utility.

Rotates local user passwords on network devices via SSH, verifies the new
credentials work before logging success, and reports per-host results.
Designed for scheduled credential hygiene on Cisco IOS/IOS-XE devices.

Prerequisites:
    pip install paramiko

Usage:
    python password_rotation.py --hosts 192.168.1.1 192.168.1.2 \
        --username admin --old-password OldPass123 --new-password NewPass456

    python password_rotation.py --inventory hosts.txt \
        --username admin --old-password OldPass123 --new-password NewPass456 \
        --port 22 --dry-run
"""

import argparse
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class RotationResult:
    host: str
    success: bool
    error: str = ""


def _open_client(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _verify_login(host: str, port: int, username: str, password: str) -> bool:
    try:
        client = _open_client(host, port, username, password)
        client.close()
        return True
    except Exception:
        return False


def _rotate_ios_password(client: paramiko.SSHClient, username: str, new_password: str) -> None:
    """Drive an interactive IOS shell to update the username secret and save."""
    shell = client.invoke_shell()
    shell.settimeout(10)

    def send_wait(cmd: str, delay: float = 0.6) -> None:
        shell.send(cmd + "\n")
        time.sleep(delay)
        while shell.recv_ready():
            shell.recv(4096)

    send_wait("enable")
    send_wait("configure terminal")
    send_wait(f"username {username} secret {new_password}")
    send_wait("end")
    send_wait("write memory", delay=2.0)
    shell.close()


def rotate_password(
    host: str,
    port: int,
    username: str,
    old_password: str,
    new_password: str,
) -> RotationResult:
    log.info("Connecting to %s", host)
    try:
        client = _open_client(host, port, username, old_password)
    except Exception as exc:
        return RotationResult(host=host, success=False, error=f"connect: {exc}")

    try:
        _rotate_ios_password(client, username, new_password)
    except Exception as exc:
        return RotationResult(host=host, success=False, error=f"rotation: {exc}")
    finally:
        client.close()

    time.sleep(1)
    if not _verify_login(host, port, username, new_password):
        log.error("%s: post-rotation verification failed — manual remediation required", host)
        return RotationResult(
            host=host,
            success=False,
            error="new credentials did not authenticate after rotation",
        )

    log.info("%s: rotation verified successfully", host)
    return RotationResult(host=host, success=True)


def load_inventory(path: str) -> List[str]:
    return [
        line.strip()
        for line in Path(path).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rotate SSH user passwords on network devices",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--hosts", nargs="+", metavar="IP", help="One or more device IPs")
    source.add_argument("--inventory", metavar="FILE", help="File with one host per line")
    parser.add_argument("--username", required=True, help="SSH username whose password is rotated")
    parser.add_argument("--old-password", required=True, help="Current password")
    parser.add_argument("--new-password", required=True, help="Replacement password")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Test connectivity with current credentials only; make no changes",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    hosts = args.hosts if args.hosts else load_inventory(args.inventory)

    if not hosts:
        log.error("No hosts to process")
        return 1

    results: List[RotationResult] = []
    for host in hosts:
        if args.dry_run:
            ok = _verify_login(host, args.port, args.username, args.old_password)
            log.info("dry-run %s: %s", host, "reachable" if ok else "UNREACHABLE")
            results.append(RotationResult(host=host, success=ok, error="" if ok else "unreachable"))
        else:
            result = rotate_password(
                host, args.port, args.username, args.old_password, args.new_password
            )
            results.append(result)

    succeeded = sum(1 for r in results if r.success)
    failed = len(results) - succeeded
    log.info("Summary: %d/%d hosts succeeded", succeeded, len(results))

    for r in results:
        if not r.success:
            log.warning("FAILED %s — %s", r.host, r.error)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())