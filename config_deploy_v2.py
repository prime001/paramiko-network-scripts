Now I have full context on existing scripts. I'll write `009_config_rollback.py` — a config rollback tool that restores a device to a previously saved backup, with before/after diff preview. This fills a real operational gap not covered by the existing scripts.

#!/usr/bin/env python3
"""
Configuration Rollback — 009_config_rollback.py

Purpose:
    Restore a Cisco IOS/IOS-XE device's running configuration to a previously
    saved backup file.  Before applying any changes the script fetches the
    current running-config, displays a unified diff so the operator can review
    exactly what will change, and prompts for confirmation unless --yes is given.

    Rollback is performed line-by-line via an interactive SSH shell using the
    device's global configuration mode; it does NOT rely on TFTP or SCP.

Usage:
    # Review diff, then confirm interactively
    python 009_config_rollback.py -d 192.168.1.1 -u admin -b backup.cfg

    # Non-interactive rollback (CI / automation)
    python 009_config_rollback.py -d 192.168.1.1 -u admin -b backup.cfg --yes

    # Preview diff only, make no changes
    python 009_config_rollback.py -d 192.168.1.1 -u admin -b backup.cfg --dry-run

    # Key-based auth, custom port
    python 009_config_rollback.py -d 10.0.0.1 -u netops -k ~/.ssh/id_rsa \
        -b backup.cfg --port 2222

Prerequisites:
    pip install paramiko
    Python 3.8+
    SSH access with privilege 15 (or 'enable' access) on the target device.
"""

import argparse
import difflib
import getpass
import logging
import sys
import time

import paramiko

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)
log = logging.getLogger(__name__)


def _drain(shell: paramiko.Channel, pause: float = 0.4) -> str:
    """Read all buffered output from an interactive shell channel."""
    shell.settimeout(pause)
    buf = []
    try:
        while True:
            chunk = shell.recv(8192)
            if not chunk:
                break
            buf.append(chunk.decode("utf-8", errors="replace"))
    except Exception:
        pass
    return "".join(buf)


def open_shell(client: paramiko.SSHClient, timeout: int = 30) -> paramiko.Channel:
    shell = client.invoke_shell(width=220, height=50)
    shell.settimeout(timeout)
    time.sleep(1.0)
    _drain(shell)  # clear banner / MOTD
    shell.send("terminal length 0\n")
    time.sleep(0.3)
    _drain(shell)
    return shell


def fetch_running_config(shell: paramiko.Channel) -> str:
    shell.send("show running-config\n")
    time.sleep(3.0)
    raw = _drain(shell, pause=1.0)
    # Strip leading prompt line and trailing prompt
    lines = raw.splitlines()
    cfg_lines = [l for l in lines if not l.strip().startswith("show running") and l.strip() != ""]
    return "\n".join(cfg_lines)


def load_backup(path: str) -> str:
    with open(path) as fh:
        return fh.read()


def show_diff(current: str, backup: str) -> int:
    """Print a unified diff. Returns the number of changed lines."""
    current_lines = current.splitlines(keepends=True)
    backup_lines = backup.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        current_lines, backup_lines,
        fromfile="running-config (current)",
        tofile="backup (target)",
    ))
    if not diff:
        print("No differences found — running config matches backup.")
        return 0
    sys.stdout.writelines(diff)
    changed = sum(1 for l in diff if l.startswith(("+", "-")) and not l.startswith(("+++", "---")))
    print(f"\n{changed} line(s) differ.")
    return changed


def apply_config(shell: paramiko.Channel, backup_text: str, delay: float = 0.15) -> None:
    log.info("Entering configuration mode…")
    shell.send("configure terminal\n")
    time.sleep(0.5)
    _drain(shell)

    lines = [l for l in backup_text.splitlines() if l.strip() and not l.strip().startswith("!")]
    log.info("Sending %d configuration lines…", len(lines))
    for line in lines:
        shell.send(line + "\n")
        time.sleep(delay)

    shell.send("end\n")
    time.sleep(0.5)
    _drain(shell)
    log.info("Exited configuration mode.")


def connect(host: str, port: int, username: str, password: str | None, key_path: str | None,
            timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": host, "port": port, "username": username,
        "timeout": timeout, "look_for_keys": False, "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
        kwargs["look_for_keys"] = True
    elif password:
        kwargs["password"] = password
    log.info("Connecting to %s:%d", host, port)
    client.connect(**kwargs)
    return client


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Roll back a network device to a saved configuration backup.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-b", "--backup", required=True, help="Path to backup config file")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("-k", "--key", help="SSH private key file")
    auth.add_argument("--password-file", help="File containing SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.15,
                        help="Delay between config lines in seconds (default: 0.15)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show diff only, do not apply changes")
    parser.add_argument("--yes", action="store_true",
                        help="Skip confirmation prompt and apply immediately")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    backup_text = load_backup(args.backup)

    password = None
    if not args.key:
        if args.password_file:
            with open(args.password_file) as fh:
                password = fh.read().strip()
        else:
            password = getpass.getpass(f"SSH password for {args.username}@{args.device}: ")

    try:
        client = connect(args.device, args.port, args.username, password, args.key, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    try:
        shell = open_shell(client, timeout=args.timeout)
        log.info("Fetching current running-config…")
        current = fetch_running_config(shell)

        changed = show_diff(current, backup_text)
        if changed == 0:
            return 0

        if args.dry_run:
            log.info("Dry-run mode — no changes applied.")
            return 0

        if not args.yes:
            answer = input("\nApply rollback? [y/N] ").strip().lower()
            if answer != "y":
                log.info("Rollback cancelled.")
                return 0

        apply_config(shell, backup_text, delay=args.delay)
        log.info("Rollback complete on %s.", args.device)

    except paramiko.SSHException as exc:
        log.error("SSH error during rollback: %s", exc)
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())