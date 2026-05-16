```python
"""
credential_rotator.py - Rotate passwords on network devices via SSH

Connects to one or more network devices using current credentials,
issues vendor-appropriate password-change commands, then verifies
the new credentials work before reporting success.

Usage:
    python credential_rotator.py --host 192.168.1.1 --username admin \
        --current-password OldPass1 --new-password NewPass2

    python credential_rotator.py --inventory hosts.txt --username admin \
        --current-password OldPass1 --new-password NewPass2 \
        --vendor cisco-ios

Prerequisites:
    pip install paramiko
    SSH must be enabled on all target devices (port 22 by default).
    Account must have privilege to change its own password.
"""

import argparse
import logging
import sys
import time
from typing import Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

VENDOR_PROFILES = {
    "cisco-ios": {
        "config_enter": ["configure terminal"],
        "change_user": "username {username} privilege 15 secret {new_password}",
        "change_enable": "enable secret {new_password}",
        "config_exit": ["end", "write memory"],
    },
    "cisco-nxos": {
        "config_enter": ["configure terminal"],
        "change_user": "username {username} password {new_password} role network-admin",
        "config_exit": ["end", "copy running-config startup-config"],
    },
    "juniper": {
        "config_enter": ["configure"],
        "change_user": (
            "set system login user {username} "
            "authentication plain-text-password-value {new_password}"
        ),
        "config_exit": ["commit", "exit"],
    },
}


def _open_ssh(
    host: str, username: str, password: str, port: int, timeout: int
) -> Optional[paramiko.SSHClient]:
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
        return client
    except paramiko.AuthenticationException:
        logger.error("[%s] Authentication failed", host)
    except paramiko.SSHException as exc:
        logger.error("[%s] SSH error: %s", host, exc)
    except OSError as exc:
        logger.error("[%s] Network error: %s", host, exc)
    return None


def _send_commands(channel: paramiko.Channel, commands: list, delay: float = 0.6) -> str:
    output = ""
    for cmd in commands:
        channel.send(cmd + "\n")
        time.sleep(delay)
        while channel.recv_ready():
            output += channel.recv(4096).decode("utf-8", errors="replace")
    return output


def rotate_password(
    host: str,
    username: str,
    current_password: str,
    new_password: str,
    vendor: str = "cisco-ios",
    port: int = 22,
    timeout: int = 10,
) -> bool:
    """Rotate the login password on one device. Returns True on success."""
    profile = VENDOR_PROFILES.get(vendor)
    if not profile:
        logger.error("Unknown vendor '%s'. Choices: %s", vendor, list(VENDOR_PROFILES))
        return False

    logger.info("[%s] Connecting with current credentials", host)
    client = _open_ssh(host, username, current_password, port, timeout)
    if client is None:
        return False

    try:
        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(4096)  # drain login banner

        cmds = list(profile["config_enter"])
        if "change_user" in profile:
            cmds.append(
                profile["change_user"].format(
                    username=username, new_password=new_password
                )
            )
        if "change_enable" in profile:
            cmds.append(profile["change_enable"].format(new_password=new_password))
        cmds += profile["config_exit"]

        output = _send_commands(shell, cmds)
        logger.debug("[%s] Rotation output:\n%s", host, output)

        for indicator in ("% Error", "Invalid input", "% Bad"):
            if indicator.lower() in output.lower():
                logger.error("[%s] Device reported an error during rotation", host)
                return False
    finally:
        client.close()

    logger.info("[%s] Verifying new credentials", host)
    verify = _open_ssh(host, username, new_password, port, timeout)
    if verify is None:
        logger.error("[%s] Verification failed — new credentials rejected", host)
        return False
    verify.close()
    logger.info("[%s] Rotation verified successfully", host)
    return True


def _load_inventory(path: str) -> list:
    hosts = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.append(line)
    except OSError as exc:
        logger.error("Cannot read inventory file: %s", exc)
        sys.exit(1)
    return hosts


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rotate SSH/login passwords on network devices"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single device IP or hostname")
    group.add_argument("--inventory", metavar="FILE", help="File with one host per line")
    parser.add_argument("--username", required=True)
    parser.add_argument("--current-password", required=True)
    parser.add_argument("--new-password", required=True)
    parser.add_argument(
        "--vendor",
        default="cisco-ios",
        choices=list(VENDOR_PROFILES),
        help="Device OS (default: cisco-ios)",
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=10, help="SSH timeout in seconds")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    hosts = [args.host] if args.host else _load_inventory(args.inventory)
    if not hosts:
        logger.error("No hosts to process")
        sys.exit(1)

    succeeded, failed = [], []
    for host in hosts:
        ok = rotate_password(
            host=host,
            username=args.username,
            current_password=args.current_password,
            new_password=args.new_password,
            vendor=args.vendor,
            port=args.port,
            timeout=args.timeout,
        )
        (succeeded if ok else failed).append(host)

    print(f"\nDone: {len(succeeded)} rotated, {len(failed)} failed")
    if failed:
        print("Failed:", ", ".join(failed))
        sys.exit(1)
```