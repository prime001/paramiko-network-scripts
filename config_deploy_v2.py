```python
"""
config_rollback.py - Network device configuration rollback utility.

Purpose:
    Rolls back a network device's running configuration to a previously
    saved backup, with diff preview and optional dry-run mode. Complements
    config_backup.py (capture) and config_deploy.py (forward deploys).

Usage:
    python config_rollback.py -d 192.168.1.1 -u admin -b router1_2024-01-15.cfg
    python config_rollback.py -d 192.168.1.1 -u admin -b router1.cfg --dry-run
    python config_rollback.py -d 192.168.1.1 -u admin -b router1.cfg --force --no-save

Prerequisites:
    pip install netmiko paramiko
    A backup config file produced by config_backup.py or equivalent.
    SSH access with configuration-write privileges on the target device.
"""

import argparse
import getpass
import logging
import sys
import time
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def load_backup(config_path: str) -> list:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Backup file not found: {config_path}")
    lines = path.read_text().splitlines()
    # Preserve meaningful bang-comments but drop pure timestamp header lines
    return [ln for ln in lines if not ln.startswith("! Last config") and not ln.startswith("! NVRAM")]


def get_running_config(conn) -> list:
    output = conn.send_command("show running-config", read_timeout=60)
    return output.splitlines()


def config_diff(current: list, rollback: list) -> tuple:
    cur = {ln.strip() for ln in current if ln.strip()}
    rbk = {ln.strip() for ln in rollback if ln.strip()}
    return sorted(cur - rbk), sorted(rbk - cur)


def push_config(conn, lines: list, device_type: str) -> bool:
    try:
        output = conn.send_config_set(lines, read_timeout=120)
        if "Invalid input" in output or "% Error" in output:
            log.error("Device reported config errors:\n%s", output[:800])
            return False
        return True
    except Exception as exc:
        log.error("Config push failed: %s", exc)
        return False


def save_config(conn, device_type: str) -> bool:
    try:
        if "juniper" in device_type:
            conn.send_command("commit", read_timeout=30)
        elif "cisco" in device_type or "arista" in device_type:
            conn.send_command("write memory", read_timeout=30)
        else:
            conn.send_command_timing("copy running-config startup-config\n")
        return True
    except Exception as exc:
        log.warning("Could not persist config: %s", exc)
        return False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Roll back a network device to a saved configuration backup.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("-b", "--backup-file", required=True, help="Path to backup config file")
    p.add_argument(
        "-t", "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--dry-run", action="store_true",
        help="Preview diff only; do not apply changes",
    )
    p.add_argument(
        "--force", action="store_true",
        help="Skip interactive confirmation prompt",
    )
    p.add_argument(
        "--no-save", action="store_true",
        help="Do not write running-config to startup-config after rollback",
    )
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def print_diff_summary(removals: list, additions: list, limit: int = 12) -> None:
    print(f"\n  Lines leaving running-config : {len(removals)}")
    for ln in removals[:limit]:
        print(f"    - {ln}")
    if len(removals) > limit:
        print(f"    ... ({len(removals) - limit} more)")

    print(f"  Lines entering running-config: {len(additions)}")
    for ln in additions[:limit]:
        print(f"    + {ln}")
    if len(additions) > limit:
        print(f"    ... ({len(additions) - limit} more)")
    print()


def main() -> int:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    try:
        rollback_lines = load_backup(args.backup_file)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1

    log.info("Loaded %d lines from %s", len(rollback_lines), args.backup_file)

    params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
        "timeout": 30,
    }

    try:
        log.info("Connecting to %s as %s", args.device, args.username)
        with ConnectHandler(**params) as conn:
            current_lines = get_running_config(conn)
            log.info("Retrieved running config (%d lines)", len(current_lines))

            removals, additions = config_diff(current_lines, rollback_lines)

            if not removals and not additions:
                log.info("Running config already matches backup. Nothing to do.")
                return 0

            print(f"\nConfig rollback diff — {args.device}:")
            print_diff_summary(removals, additions)

            if args.dry_run:
                log.info("Dry run complete. No changes applied.")
                return 0

            if not args.force:
                answer = input(
                    f"Apply rollback to {args.device}? "
                    "This will overwrite the running config. [y/N]: "
                )
                if answer.strip().lower() != "y":
                    log.info("Rollback cancelled.")
                    return 0

            log.info("Applying rollback config to %s ...", args.device)
            t0 = time.monotonic()
            ok = push_config(conn, rollback_lines, args.device_type)
            elapsed = time.monotonic() - t0

            if not ok:
                log.error("Rollback failed after %.1fs", elapsed)
                return 1

            log.info("Rollback applied in %.1fs", elapsed)

            if not args.no_save:
                if save_config(conn, args.device_type):
                    log.info("Running config saved to startup-config")
                else:
                    log.warning("Changes are live but NOT persisted to startup-config")

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out reaching %s", args.device)
        return 1
    except KeyboardInterrupt:
        log.info("Aborted by user")
        return 130
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        if args.verbose:
            raise
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```