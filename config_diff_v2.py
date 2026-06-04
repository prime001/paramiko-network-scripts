```python
"""
config_drift_monitor.py - Detect unauthorized configuration changes on network devices.

Purpose:
    Connects to a network device, retrieves the running configuration, and compares
    it against a saved baseline. Reports any drift (additions, removals) since the
    baseline was established. Useful for change management audits and detecting
    unauthorized modifications between maintenance windows.

Usage:
    # Save initial baseline:
    python config_drift_monitor.py -H 192.168.1.1 -u admin -p secret --save-baseline

    # Check for drift against saved baseline:
    python config_drift_monitor.py -H 192.168.1.1 -u admin -p secret

    # Write diff to file instead of stdout:
    python config_drift_monitor.py -H 192.168.1.1 -u admin -p secret --output /tmp/drift.diff

Prerequisites:
    pip install paramiko

Exit codes: 0 = clean, 1 = error, 2 = drift detected (useful for CI/alerting pipelines).
"""

import argparse
import difflib
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


def ssh_connect(
    host: str, username: str, password: str, port: int = 22, timeout: int = 30
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def get_running_config(client: paramiko.SSHClient, command: str) -> str:
    channel = client.invoke_shell()
    channel.settimeout(30)
    time.sleep(1)
    while channel.recv_ready():
        channel.recv(4096)

    channel.send("terminal length 0\n")
    time.sleep(0.5)
    while channel.recv_ready():
        channel.recv(4096)

    channel.send(f"{command}\n")
    time.sleep(3)

    output = ""
    while True:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="replace")
            output += chunk
        else:
            time.sleep(0.5)
            if not channel.recv_ready():
                break

    channel.close()
    return output


def strip_volatile_lines(config: str) -> list:
    """Drop lines that legitimately change on every reload (timestamps, clock-period)."""
    volatile_prefixes = (
        "! Last configuration change",
        "! NVRAM config last updated",
        "ntp clock-period",
    )
    lines = []
    for line in config.splitlines():
        if any(line.strip().startswith(p) for p in volatile_prefixes):
            continue
        lines.append(line)
    return lines


def compute_diff(baseline: list, current: list, label_a: str, label_b: str) -> str:
    diff = difflib.unified_diff(
        baseline,
        current,
        fromfile=label_a,
        tofile=label_b,
        lineterm="",
    )
    return "\n".join(diff)


def default_baseline_path(host: str) -> str:
    safe = host.replace(".", "_").replace(":", "_")
    return os.path.join(os.getcwd(), f"{safe}_baseline.txt")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Detect config drift on a network device by comparing live config "
            "against a previously saved baseline."
        )
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--baseline-file",
        help="Baseline file path (default: <host>_baseline.txt in cwd)",
    )
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Capture current config as the new baseline and exit",
    )
    parser.add_argument(
        "--command",
        default="show running-config",
        help="Command to retrieve config (default: 'show running-config')",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="SSH connection timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--output",
        help="Write drift report to this file instead of stdout",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    baseline_file = args.baseline_file or default_baseline_path(args.host)

    logger.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        client = ssh_connect(args.host, args.username, args.password, args.port, args.timeout)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except Exception as exc:
        logger.error("Connection error: %s", exc)
        return 1

    try:
        logger.info("Running: %s", args.command)
        raw = get_running_config(client, args.command)
    except Exception as exc:
        logger.error("Failed to retrieve config: %s", exc)
        return 1
    finally:
        client.close()

    current_lines = strip_volatile_lines(raw)

    if args.save_baseline:
        path = Path(baseline_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(current_lines))
        logger.info("Baseline saved: %s (%d lines)", baseline_file, len(current_lines))
        print(f"Baseline saved: {baseline_file}")
        return 0

    baseline_path = Path(baseline_file)
    if not baseline_path.exists():
        logger.error("No baseline at %s — run with --save-baseline first", baseline_file)
        return 1

    baseline_lines = baseline_path.read_text().splitlines()
    diff = compute_diff(
        baseline_lines,
        current_lines,
        label_a=baseline_file,
        label_b=f"{args.host} (live {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')})",
    )

    if not diff:
        msg = f"[{datetime.now().isoformat()}] CLEAN: no drift detected on {args.host}"
        logger.info("No drift detected on %s", args.host)
        print(msg)
        return 0

    diff_lines = diff.splitlines()
    added = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
    logger.warning("DRIFT on %s: +%d lines, -%d lines", args.host, added, removed)

    report = (
        f"# Config Drift Report\n"
        f"# Host:      {args.host}\n"
        f"# Timestamp: {datetime.now().isoformat()}\n"
        f"# Baseline:  {baseline_file}\n"
        f"# Added:     +{added} lines\n"
        f"# Removed:   -{removed} lines\n\n"
        f"{diff}\n"
    )

    if args.output:
        Path(args.output).write_text(report)
        logger.info("Report written to %s", args.output)
    else:
        print(report)

    return 2


if __name__ == "__main__":
    sys.exit(main())
```