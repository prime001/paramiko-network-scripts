#!/usr/bin/env python3
"""
config_diff_devices.py — Compare running configurations between two network devices.

Purpose:
    Identifies configuration drift between two devices (e.g., HA pairs, redundant
    routers, or same-role switches) by fetching their running configs via SSH and
    producing a unified diff. Useful for change audits and consistency checks.

Usage:
    python config_diff_devices.py \\
        --host1 192.168.1.1 --host2 192.168.1.2 \\
        --username admin --password secret \\
        [--port 22] [--timeout 30] [--output diff.txt] [--context 5]

Prerequisites:
    pip install paramiko
    SSH access to both devices with a user that has "show running-config" privilege.
"""

import argparse
import difflib
import logging
import sys
import time
from datetime import datetime
from getpass import getpass

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

PROMPT_PATTERNS = [b"#", b">"]
READ_TIMEOUT = 2.0
RECV_CHUNK = 65535


def _recv_until_prompt(channel, timeout: float = READ_TIMEOUT) -> str:
    """Read from channel until a CLI prompt character appears or timeout."""
    buf = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            buf += channel.recv(RECV_CHUNK)
            if any(buf.rstrip().endswith(p) for p in PROMPT_PATTERNS):
                break
        else:
            time.sleep(0.05)
    return buf.decode("utf-8", errors="replace")


def fetch_running_config(host: str, port: int, username: str, password: str,
                         timeout: int) -> list[str]:
    """
    Open an SSH session, drop into enable mode if needed, retrieve the running
    config, and return it as a list of lines (stripped of terminal artefacts).
    """
    log.info("Connecting to %s:%d", host, port)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except Exception as exc:
        log.error("Cannot connect to %s: %s", host, exc)
        raise

    channel = client.invoke_shell(width=512, height=200)
    _recv_until_prompt(channel, timeout=5.0)

    # Disable paging so the full config arrives in one shot
    for cmd in ("terminal length 0\n", "terminal width 0\n",
                "show running-config\n"):
        channel.send(cmd)
        time.sleep(0.3)

    raw = _recv_until_prompt(channel, timeout=READ_TIMEOUT * 15)
    channel.close()
    client.close()

    lines = raw.splitlines()
    # Drop the echoed command and the final prompt line
    trimmed = [
        ln for ln in lines
        if not ln.strip().endswith("#")
        and "show running-config" not in ln
        and "terminal " not in ln
    ]
    return trimmed


def diff_configs(lines_a: list[str], lines_b: list[str],
                 label_a: str, label_b: str,
                 context: int) -> list[str]:
    """Return unified diff lines between two config line lists."""
    return list(
        difflib.unified_diff(
            lines_a,
            lines_b,
            fromfile=label_a,
            tofile=label_b,
            lineterm="",
            n=context,
        )
    )


def build_report(host1: str, host2: str, diff_lines: list[str]) -> str:
    """Wrap diff output in a human-readable report."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    banner = [
        f"Config Diff Report — {ts}",
        f"Device A : {host1}",
        f"Device B : {host2}",
        "-" * 60,
    ]
    if diff_lines:
        body = diff_lines
    else:
        body = ["(no differences found — configurations are identical)"]
    return "\n".join(banner + body) + "\n"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Compare running configs on two network devices.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host1", required=True, help="First device IP/hostname")
    p.add_argument("--host2", required=True, help="Second device IP/hostname")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", default=None,
                   help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--timeout", type=int, default=30,
                   help="SSH connection timeout (seconds)")
    p.add_argument("--context", type=int, default=3,
                   help="Diff context lines")
    p.add_argument("--output", default=None,
                   help="Write report to this file instead of stdout")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    password = args.password or getpass(f"Password for {args.username}: ")

    try:
        cfg1 = fetch_running_config(
            args.host1, args.port, args.username, password, args.timeout)
        cfg2 = fetch_running_config(
            args.host2, args.port, args.username, password, args.timeout)
    except Exception:
        sys.exit(1)

    diff = diff_configs(cfg1, cfg2, args.host1, args.host2, args.context)
    report = build_report(args.host1, args.host2, diff)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report)
        log.info("Report written to %s", args.output)
    else:
        print(report)

    sys.exit(0 if not diff else 1)