```python
"""
startup_config_sync.py - Detect and optionally resolve unsaved configuration changes.

Purpose:
    Compares running-config against startup-config on Cisco IOS/IOS-XE devices
    to identify unsaved changes. Optionally saves running config to startup
    ('write memory') and/or archives both configs locally for audit purposes.

Usage:
    python startup_config_sync.py -H 192.168.1.1 -u admin -p secret
    python startup_config_sync.py -H 192.168.1.1 -u admin -p secret --save
    python startup_config_sync.py -H 192.168.1.1 -u admin -p secret --save --archive ./backups

Prerequisites:
    - pip install paramiko
    - SSH access to target device
    - Account with privilege 15 (or enable capability if using --save)
"""

import argparse
import difflib
import getpass
import logging
import os
import re
import sys
import time
from datetime import datetime

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def run_command(shell, command, wait=2.0, buffer_size=65535):
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        chunk = shell.recv(buffer_size).decode("utf-8", errors="replace")
        output += chunk
        if chunk:
            time.sleep(0.3)
    return output


def strip_preamble(config_text):
    """Remove timestamp/header lines that differ between running and startup."""
    lines = config_text.splitlines()
    cleaned = []
    for line in lines:
        if re.match(r"^(Building configuration|Current configuration|!.*Last configuration)", line):
            continue
        if re.match(r"^! Last configuration change", line):
            continue
        if re.match(r"^! NVRAM config last updated", line):
            continue
        cleaned.append(line)
    return "\n".join(cleaned)


def fetch_config(shell, config_type="running"):
    """Fetch running or startup config, handling --More-- pagination."""
    cmd = f"show {config_type}-config"
    shell.send("terminal length 0\n")
    time.sleep(1)
    shell.recv(65535)

    shell.send(cmd + "\n")
    time.sleep(3)

    output = ""
    deadline = time.time() + 60
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            time.sleep(0.5)
        else:
            if output and re.search(r"#\s*$", output.splitlines()[-1] if output.splitlines() else ""):
                break
            time.sleep(0.5)

    return strip_preamble(output)


def write_memory(shell):
    log.info("Saving running config to startup (write memory)...")
    shell.send("write memory\n")
    time.sleep(4)
    response = ""
    while shell.recv_ready():
        response += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.3)
    if "OK" in response or "success" in response.lower() or "[OK]" in response:
        log.info("Configuration saved successfully.")
        return True
    log.warning("Save may have failed. Response: %s", response.strip())
    return False


def archive_config(config_text, host, config_type, archive_dir):
    os.makedirs(archive_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{host}_{config_type}_{timestamp}.txt"
    filepath = os.path.join(archive_dir, filename)
    with open(filepath, "w") as fh:
        fh.write(config_text)
    log.info("Archived %s-config to %s", config_type, filepath)
    return filepath


def compare_configs(running, startup):
    run_lines = running.splitlines(keepends=True)
    start_lines = startup.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        start_lines, run_lines,
        fromfile="startup-config",
        tofile="running-config",
        n=3,
    ))
    return diff


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect unsaved config changes on Cisco IOS/IOS-XE devices."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--save",
        action="store_true",
        help="Write running-config to startup-config if differences found",
    )
    parser.add_argument(
        "--archive",
        metavar="DIR",
        help="Directory to archive both configs (e.g. ./backups)",
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="SSH connection timeout in seconds"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = ssh_connect(args.host, args.username, password, args.port, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell(width=200, height=200)
        time.sleep(1.5)
        shell.recv(65535)  # drain banner

        log.info("Fetching running-config...")
        running = fetch_config(shell, "running")

        log.info("Fetching startup-config...")
        startup = fetch_config(shell, "startup")

        if args.archive:
            archive_config(running, args.host, "running", args.archive)
            archive_config(startup, args.host, "startup", args.archive)

        diff = compare_configs(running, startup)

        if not diff:
            print(f"\n[OK] {args.host}: running-config matches startup-config. No unsaved changes.")
        else:
            added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
            removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
            print(f"\n[WARN] {args.host}: Unsaved changes detected (+{added} lines / -{removed} lines)\n")
            print("".join(diff[:80]))
            if len(diff) > 80:
                print(f"... ({len(diff) - 80} more diff lines)")

            if args.save:
                saved = write_memory(shell)
                if not saved:
                    sys.exit(2)
            else:
                print("\nRun with --save to persist changes to startup-config.")
                sys.exit(1)

    finally:
        client.close()


if __name__ == "__main__":
    main()
```