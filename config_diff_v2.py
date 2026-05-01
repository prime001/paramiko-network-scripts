```python
"""
running_vs_startup_diff.py — Compare running-config against startup-config on
a Cisco IOS/IOS-XE device via SSH and report unsaved changes.

Purpose:
    Operators routinely make live changes without saving them. Any unsaved
    change is lost on reload. This script SSHes to a device, fetches both
    configs, and prints a unified diff — making it safe to schedule as a
    cron check or wire into a monitoring pipeline.

Usage:
    python running_vs_startup_diff.py -H 192.168.1.1 -u admin
    python running_vs_startup_diff.py -H 10.0.0.1 -u admin -p secret -n 5
    python running_vs_startup_diff.py -H 192.168.1.1 -u admin -k ~/.ssh/id_rsa --exit-code

Prerequisites:
    pip install paramiko
    SSH enabled on the device; user must have privilege level >= 1.
    IOS devices: 'ip ssh version 2' recommended.
"""

import argparse
import difflib
import getpass
import logging
import sys
import time

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def read_until_prompt(channel, timeout=45):
    """Accumulate channel output until a device prompt (ends with '#') appears."""
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            buf += channel.recv(131072).decode("utf-8", errors="replace")
            last = buf.rstrip().splitlines()
            if last and last[-1].rstrip().endswith("#"):
                break
        else:
            time.sleep(0.05)
    return buf


def clean_output(raw, command):
    """Strip echoed command and trailing prompt; return config body lines."""
    lines = raw.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if command.split()[-1] in line:
            start = i + 1
            break
    while start < len(lines) and not lines[start].strip():
        start += 1
    end = len(lines)
    while end > start and (not lines[end - 1].strip() or lines[end - 1].rstrip().endswith("#")):
        end -= 1
    return lines[start:end]


def fetch_both_configs(client):
    channel = client.invoke_shell(width=250, height=50)
    time.sleep(1)
    channel.recv(131072)  # drain login banner

    channel.send("terminal length 0\n")
    read_until_prompt(channel, timeout=10)

    log.info("Fetching running-config")
    channel.send("show running-config\n")
    running_raw = read_until_prompt(channel)

    log.info("Fetching startup-config")
    channel.send("show startup-config\n")
    startup_raw = read_until_prompt(channel)

    channel.close()
    return (
        clean_output(running_raw, "show running-config"),
        clean_output(startup_raw, "show startup-config"),
    )


def connect(host, port, username, password, key_path):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 15,
        "look_for_keys": bool(key_path),
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(2)
    except paramiko.SSHException as exc:
        log.error("SSH negotiation failed: %s", exc)
        sys.exit(2)
    except OSError as exc:
        log.error("Connection refused or timed out: %s", exc)
        sys.exit(2)
    return client


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Diff running-config vs startup-config on a Cisco device. "
            "Exits 0 if configs match, 1 if unsaved changes exist (with --exit-code)."
        )
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("-k", "--key", dest="key_path", default=None, help="Path to SSH private key")
    parser.add_argument(
        "-n", "--context", type=int, default=3, metavar="LINES",
        help="Unified diff context lines (default: 3)",
    )
    parser.add_argument(
        "--exit-code", action="store_true",
        help="Return exit status 1 when unsaved changes are found",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password
    if not args.key_path and not password:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    log.info("Connecting to %s:%d", args.host, args.port)
    client = connect(args.host, args.port, args.username, password, args.key_path)
    try:
        running_lines, startup_lines = fetch_both_configs(client)
    finally:
        client.close()

    diff = list(
        difflib.unified_diff(
            [l + "\n" for l in startup_lines],
            [l + "\n" for l in running_lines],
            fromfile=f"{args.host}:startup-config",
            tofile=f"{args.host}:running-config",
            n=args.context,
        )
    )

    if not diff:
        log.info("CLEAN — running-config matches startup-config on %s", args.host)
        sys.exit(0)

    log.warning("UNSAVED CHANGES — %d diff line(s) on %s", len(diff), args.host)
    sys.stdout.writelines(diff)
    sys.exit(1 if args.exit_code else 0)


if __name__ == "__main__":
    main()
```