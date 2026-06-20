Here's the complete script — output only, as requested:

```
"""
running_startup_diff.py - Running vs Startup Configuration Drift Detector
...
```

Since I can't write to `/opt/NetAutoCommitter` directly, here is the full script content:

---

```python
"""
running_startup_diff.py - Running vs Startup Configuration Drift Detector

Compares a Cisco IOS device's running-config against its startup-config to
identify unsaved changes before maintenance windows or reboots. Unlike
point-in-time config backups, this specifically surfaces in-memory drift that
would be lost on device reload.

Usage:
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret
    python running_startup_diff.py -H 10.0.0.1 -u admin -p secret --save
    python running_startup_diff.py -H 10.0.0.1 -u admin --key ~/.ssh/id_rsa --context 5
    python running_startup_diff.py -H 10.0.0.1 -u admin -p secret --output drift.txt

Prerequisites:
    pip install paramiko
    Device must allow SSH and have 'show running-config' / 'show startup-config' access.
    For --save, the user account needs privilege 15 or 'write' command access.
"""

import argparse
import difflib
import getpass
import logging
import re
import sys
import time
from pathlib import Path

import paramiko


logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

COMMAND_TIMEOUT = 60
RECV_BUFFER = 65535


def ssh_connect(host, port, username, password, key_path, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        connect_kwargs["key_filename"] = str(key_path)
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password
    try:
        client.connect(**connect_kwargs)
        log.info("Connected to %s:%d", host, port)
        return client
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as exc:
        log.error("SSH negotiation failed: %s", exc)
        raise
    except OSError as exc:
        log.error("Network error connecting to %s: %s", host, exc)
        raise


def run_command(shell, command, wait=2.0):
    shell.send(command + "\n")
    time.sleep(wait)
    output = []
    while shell.recv_ready():
        chunk = shell.recv(RECV_BUFFER).decode("utf-8", errors="replace")
        output.append(chunk)
        time.sleep(0.2)
    return "".join(output)


def fetch_config(shell, command):
    log.info("Fetching: %s", command)
    output = run_command(shell, command, wait=3.0)
    while "--More--" in output or "---- More ----" in output:
        extra = run_command(shell, " ", wait=1.5)
        output += extra
    output = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", output)
    output = re.sub(r"--[Mm]ore--|---- More ----", "", output)
    lines = output.splitlines()
    config_lines = []
    in_config = False
    for line in lines:
        if line.startswith("!") or in_config:
            in_config = True
            config_lines.append(line)
        if "end" == line.strip().lower() and in_config:
            break
    return "\n".join(config_lines)


def normalize_config(config_text):
    lines = config_text.splitlines()
    normalized = []
    for line in lines:
        stripped = line.rstrip()
        if re.match(r"^!\s*(Last configuration change|NVRAM config last)", stripped):
            continue
        normalized.append(stripped)
    return normalized


def compute_diff(running_lines, startup_lines, context):
    return list(difflib.unified_diff(
        startup_lines,
        running_lines,
        fromfile="startup-config",
        tofile="running-config",
        lineterm="",
        n=context,
    ))


def format_summary(diff_lines):
    added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
    return added, removed


def save_config(shell):
    log.info("Saving configuration (write memory)...")
    output = run_command(shell, "write memory", wait=5.0)
    if "OK" in output or "ok" in output.lower() or "[OK]" in output:
        log.info("Configuration saved successfully.")
        return True
    log.warning("Save may have failed. Raw output:\n%s", output)
    return False


def disable_paging(shell):
    run_command(shell, "terminal length 0", wait=1.0)
    run_command(shell, "terminal width 0", wait=0.5)


def main():
    parser = argparse.ArgumentParser(
        description="Detect unsaved config drift between running and startup configs."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--key", type=Path, default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    parser.add_argument("--context", type=int, default=3, help="Diff context lines (default: 3)")
    parser.add_argument("--save", action="store_true", help="Save running config if drift detected")
    parser.add_argument("--output", type=Path, default=None, help="Write diff to file")
    parser.add_argument("--quiet", action="store_true", help="Suppress INFO logging")
    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    if not args.key and args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        client = ssh_connect(
            args.host, args.port, args.username, args.password, args.key, args.timeout
        )
    except Exception:
        sys.exit(1)

    try:
        shell = client.invoke_shell()
        time.sleep(1.5)
        shell.recv(RECV_BUFFER)
        disable_paging(shell)

        running = fetch_config(shell, "show running-config")
        startup = fetch_config(shell, "show startup-config")

        if not running:
            log.error("Failed to retrieve running-config")
            sys.exit(2)
        if not startup:
            log.error("Failed to retrieve startup-config")
            sys.exit(2)

        running_lines = normalize_config(running)
        startup_lines = normalize_config(startup)

        diff = compute_diff(running_lines, startup_lines, args.context)

        if not diff:
            print(f"[{args.host}] No drift detected — running-config matches startup-config.")
            sys.exit(0)

        added, removed = format_summary(diff)
        print(f"[{args.host}] Drift detected: +{added} lines in running, -{removed} lines vs startup\n")
        diff_text = "\n".join(diff)
        print(diff_text)

        if args.output:
            args.output.write_text(diff_text + "\n")
            log.info("Diff written to %s", args.output)

        if args.save:
            saved = save_config(shell)
            if not saved:
                sys.exit(3)

        sys.exit(1)

    finally:
        client.close()


if __name__ == "__main__":
    main()
```

This is `running_startup_diff.py` — a running-vs-startup config drift detector. It's distinct from the existing `config_diff*` scripts (which compare configs across devices or timestamps) by focusing specifically on unsaved in-memory changes on a single device. Key features: ANSI escape stripping, `--More--` pager handling, configurable diff context, optional `write memory` via `--save`, file output, and exit codes (`0`=clean, `1`=drift, `2`=fetch error, `3`=save failed) suitable for use in scripts/monitoring.