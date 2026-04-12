```python
"""
config_diff.py - Network Device Configuration Diff Tool

Purpose:
    Connects to a network device via SSH and compares the current running
    configuration against a local baseline file or the device's startup
    configuration. Outputs a unified diff to identify configuration drift.

Usage:
    # Compare running config to a local baseline:
    python config_diff.py -H 192.168.1.1 -u admin -b /backups/router1_baseline.txt

    # Compare running config to startup config on device:
    python config_diff.py -H 192.168.1.1 -u admin --vs-startup

    # Save current running config as new baseline:
    python config_diff.py -H 192.168.1.1 -u admin --save-baseline /backups/router1_baseline.txt

    # Output diff to file instead of stdout:
    python config_diff.py -H 192.168.1.1 -u admin -b baseline.txt -o diff_report.txt

Prerequisites:
    pip install paramiko
    SSH access to target device (IOS, IOS-XE, NX-OS, EOS)
    Credentials with privilege level to run 'show running-config'
"""

import argparse
import difflib
import getpass
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

COMMAND_TIMEOUT = 60
RECV_BUFFER = 65535
PROMPT_WAIT = 2.0


def fetch_device_config(client: paramiko.SSHClient, command: str) -> str:
    """Execute a command on the device and return the full output."""
    channel = client.invoke_shell()
    channel.settimeout(COMMAND_TIMEOUT)

    time.sleep(PROMPT_WAIT)
    # Drain initial banner/prompt
    if channel.recv_ready():
        channel.recv(RECV_BUFFER)

    channel.send(command + "\n")
    time.sleep(PROMPT_WAIT)

    output_parts = []
    deadline = time.time() + COMMAND_TIMEOUT
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(RECV_BUFFER).decode("utf-8", errors="replace")
            output_parts.append(chunk)
            # Simple heuristic: stop when prompt reappears after output
            if chunk.rstrip().endswith(("#", ">", "$")):
                break
        elif output_parts:
            # No more data and we already got some — done
            break
        time.sleep(0.3)

    channel.close()
    raw = "".join(output_parts)
    # Strip the echoed command and trailing prompt line
    lines = raw.splitlines()
    filtered = [
        ln for ln in lines
        if not ln.strip().startswith(command.strip()[:10])
        and not ln.strip().endswith(("#", ">"))
    ]
    return "\n".join(filtered)


def normalize_config(config_text: str) -> list[str]:
    """Strip blank lines and trailing whitespace for cleaner diffs."""
    return [
        line.rstrip() + "\n"
        for line in config_text.splitlines()
        if line.strip()
    ]


def build_diff(
    from_lines: list[str],
    to_lines: list[str],
    from_label: str,
    to_label: str,
) -> str:
    """Return a unified diff string between two config line lists."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    diff = difflib.unified_diff(
        from_lines,
        to_lines,
        fromfile=f"{from_label} ({timestamp})",
        tofile=f"{to_label} ({timestamp})",
        lineterm="",
    )
    return "\n".join(diff)


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    """Establish an SSH connection, returning the client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info("Connecting to %s:%d as %s", host, port, username)
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    log.info("Connected successfully")
    return client


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare network device running config to a baseline or startup config"
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "-b", "--baseline",
        metavar="FILE",
        help="Local baseline file to diff against",
    )
    mode.add_argument(
        "--vs-startup",
        action="store_true",
        help="Diff running config against startup config on the device",
    )
    mode.add_argument(
        "--save-baseline",
        metavar="FILE",
        help="Save running config to FILE as new baseline (no diff performed)",
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write diff output to FILE instead of stdout",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress info logging; only print diff",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.quiet:
        log.setLevel(logging.WARNING)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        client = connect(args.host, args.port, args.username, password)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("SSH connection error: %s", exc)
        return 1

    try:
        log.info("Fetching running configuration...")
        running_raw = fetch_device_config(client, "show running-config")
        if not running_raw.strip():
            log.error("No output received from 'show running-config'")
            return 1
        running_lines = normalize_config(running_raw)

        # -- Save baseline mode --
        if args.save_baseline:
            dest = Path(args.save_baseline)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(running_raw)
            log.info("Baseline saved to %s (%d lines)", dest, len(running_lines))
            return 0

        # -- Diff vs startup config --
        if args.vs_startup:
            log.info("Fetching startup configuration...")
            startup_raw = fetch_device_config(client, "show startup-config")
            compare_lines = normalize_config(startup_raw)
            from_label = f"{args.host}:startup-config"
            to_label = f"{args.host}:running-config"
            diff = build_diff(compare_lines, running_lines, from_label, to_label)

        # -- Diff vs local baseline file --
        else:
            baseline_path = Path(args.baseline)
            if not baseline_path.exists():
                log.error("Baseline file not found: %s", baseline_path)
                return 1
            baseline_raw = baseline_path.read_text()
            compare_lines = normalize_config(baseline_raw)
            from_label = str(baseline_path)
            to_label = f"{args.host}:running-config"
            diff = build_diff(compare_lines, running_lines, from_label, to_label)

    finally:
        client.close()
        log.info("Connection closed")

    if not diff.strip():
        log.info("No differences found — configurations match")
        return 0

    changed_lines = sum(1 for ln in diff.splitlines() if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---")))
    log.info("Diff contains %d changed lines", changed_lines)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(diff)
        log.info("Diff written to %s", out_path)
    else:
        print(diff)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```