running_startup_diff.py - Detect unsaved configuration changes on network devices.

Compares the running configuration against the startup configuration to identify
changes that will be lost on the next device reload. Useful for compliance audits,
change management workflows, and pre-maintenance checks.

Usage:
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret
    python running_startup_diff.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret --output diff.txt
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret --exit-code

Prerequisites:
    pip install paramiko
    Device must support 'show running-config' and 'show startup-config' (IOS/IOS-XE).
    For other platforms, adjust the fetch commands accordingly.
"""

import argparse
import difflib
import logging
import sys
import time
from datetime import datetime

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def ssh_connect(host, port, username, password=None, key_path=None, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("Either --password or --key must be provided")
    client.connect(**connect_kwargs)
    return client


def run_command(shell, command, wait=1.0):
    shell.send(command + "\n")
    time.sleep(wait)
    if shell.recv_ready():
        shell.recv(65535)


def fetch_config(shell, command, idle_timeout=5, max_wait=60):
    """Fetch full config output, handling --More-- pagination."""
    shell.send(command + "\n")
    output = ""
    deadline = time.time() + max_wait
    last_recv = time.time()
    while time.time() < deadline:
        time.sleep(0.3)
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            last_recv = time.time()
            if "--More--" in chunk:
                shell.send(" ")
        elif time.time() - last_recv > idle_timeout:
            break
    return output


def strip_preamble(config_text):
    """Remove shell prompts and pagination artifacts from raw output."""
    lines = []
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.endswith("#") or stripped.endswith(">"):
            continue
        if "--More--" in stripped:
            continue
        lines.append(line.rstrip())
    return "\n".join(lines)


def diff_configs(running, startup):
    running_lines = running.splitlines(keepends=True)
    startup_lines = startup.splitlines(keepends=True)
    return list(difflib.unified_diff(
        startup_lines,
        running_lines,
        fromfile="startup-config",
        tofile="running-config",
        lineterm="",
    ))


def main():
    parser = argparse.ArgumentParser(
        description="Compare running vs startup config to detect unsaved changes."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("-k", "--key", default=None, metavar="KEY_FILE", help="SSH private key path")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write diff to file")
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 if unsaved changes detected (useful in CI checks)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key:
        parser.error("Provide --password or --key for authentication")

    log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        client = ssh_connect(
            args.host, args.port, args.username,
            password=args.password, key_path=args.key,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(2)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(2)

    try:
        shell = client.invoke_shell(width=200, height=200)
        time.sleep(1)
        shell.recv(65535)  # drain login banner

        run_command(shell, "terminal length 0", wait=1.0)

        log.info("Fetching running-config")
        raw_running = fetch_config(shell, "show running-config")

        log.info("Fetching startup-config")
        raw_startup = fetch_config(shell, "show startup-config")
    finally:
        client.close()

    running = strip_preamble(raw_running)
    startup = strip_preamble(raw_startup)

    diff = diff_configs(running, startup)

    if not diff:
        print(f"[{args.host}] Running config matches startup config — no unsaved changes.")
        log.info("No differences found")
        sys.exit(0)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    diff_text = f"# Unsaved changes on {args.host} — {timestamp}\n" + "".join(diff)

    print(diff_text)
    log.warning("%d diff lines — device has unsaved changes", len(diff))

    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(diff_text)
            log.info("Diff written to %s", args.output)
        except OSError as exc:
            log.error("Failed to write output file: %s", exc)

    if args.exit_code:
        sys.exit(1)


if __name__ == "__main__":
    main()