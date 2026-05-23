```python
"""
running_startup_diff.py - Detect unsaved configuration changes on network devices.

Compares running-config vs startup-config via SSH to identify changes that
would be lost on reboot. Useful for pre-maintenance checks and post-incident audits.

Usage:
    python running_startup_diff.py -d 192.168.1.1 -u admin -p secret
    python running_startup_diff.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python running_startup_diff.py -d 192.168.1.1 -u admin -p secret --save

Prerequisites:
    pip install paramiko
    SSH must be enabled; user requires privilege level 15 (enable mode).
"""

import argparse
import difflib
import logging
import re
import sys
import time
from getpass import getpass

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

PROMPT_RE = re.compile(r"[\w\-\.]+[#>]\s*$", re.MULTILINE)


def connect(host, username, password=None, key_file=None, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host, "port": port, "username": username,
        "timeout": timeout, "look_for_keys": False, "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def recv_until_prompt(shell, timeout=45):
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            output += shell.recv(65535).decode("utf-8", errors="replace")
            if PROMPT_RE.search(output):
                break
        else:
            time.sleep(0.1)
    return output


def send_command(shell, command, timeout=45):
    shell.send(command + "\n")
    return recv_until_prompt(shell, timeout=timeout)


def strip_config_noise(raw):
    lines = raw.splitlines()
    result = []
    for line in lines:
        if PROMPT_RE.match(line) or PROMPT_RE.match(line.strip()):
            continue
        if "Building configuration" in line or "Current configuration" in line:
            continue
        result.append(line)
    while result and not result[0].strip():
        result.pop(0)
    while result and not result[-1].strip():
        result.pop()
    return "\n".join(result)


def diff_configs(startup, running):
    a = startup.splitlines(keepends=True)
    b = running.splitlines(keepends=True)
    return list(difflib.unified_diff(
        a, b, fromfile="startup-config", tofile="running-config", lineterm="",
    ))


def print_diff(diff, use_color):
    if not diff:
        print("  No differences — running and startup configs are identical.")
        return
    for line in diff:
        line = line.rstrip("\n")
        if use_color and sys.stdout.isatty():
            if line.startswith("+") and not line.startswith("+++"):
                print(f"\033[32m{line}\033[0m")
            elif line.startswith("-") and not line.startswith("---"):
                print(f"\033[31m{line}\033[0m")
            elif line.startswith("@@"):
                print(f"\033[36m{line}\033[0m")
            else:
                print(line)
        else:
            print(line)


def parse_args():
    p = argparse.ArgumentParser(
        description="Diff running-config vs startup-config on a Cisco IOS device.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("--key", metavar="KEYFILE", help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    p.add_argument("--save", action="store_true", help="Run 'write memory' if configs differ")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    password = args.password
    if not password and not args.key:
        password = getpass(f"Password for {args.username}@{args.device}: ")

    logger.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = connect(
            args.device, args.username, password=password,
            key_file=args.key, port=args.port, timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed")
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell(width=220, height=500)
        recv_until_prompt(shell, timeout=10)
        send_command(shell, "terminal length 0")

        logger.info("Fetching running-config")
        running = strip_config_noise(send_command(shell, "show running-config", timeout=60))

        logger.info("Fetching startup-config")
        startup = strip_config_noise(send_command(shell, "show startup-config", timeout=60))

        diff = diff_configs(startup, running)
        changed = sum(
            1 for l in diff
            if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))
        )

        print(f"\n=== {args.device}: running vs startup-config ===\n")
        print_diff(diff, use_color=not args.no_color)

        if diff:
            print(f"\n  Summary: {changed} line(s) differ — unsaved changes present.")
            if args.save:
                logger.info("Writing memory on %s", args.device)
                send_command(shell, "write memory", timeout=30)
                print("  Configuration saved (write memory executed).")
        else:
            print()

    finally:
        client.close()
        logger.debug("Connection closed")


if __name__ == "__main__":
    main()
```