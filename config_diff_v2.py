#!/usr/bin/env python3
"""config_baseline_checker.py - Detect configuration drift against a golden baseline.

Purpose:
    Connects to a network device via SSH, retrieves the running configuration,
    and diffs it against a locally stored golden/baseline config file. Useful
    for compliance audits, change-window verification, and automated drift
    detection in CI pipelines.

Usage:
    python config_baseline_checker.py -H 192.168.1.1 -u admin -b golden.cfg
    python config_baseline_checker.py -H 192.168.1.1 -u admin -b golden.cfg --format summary
    python config_baseline_checker.py -H 192.168.1.1 -u admin -b golden.cfg --save-running out.cfg --format json

    Exit code 0 = no drift, 1 = drift detected or error.

Prerequisites:
    pip install paramiko
    Python 3.9+
"""

import argparse
import difflib
import json
import logging
import sys
import time
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

import paramiko

LOG = logging.getLogger(__name__)

_VOLATILE_PREFIXES = (
    "! Last configuration change",
    "! NVRAM config last updated",
    "Building configuration",
    "Current configuration",
    "ntp clock-period",
)


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG if verbose else logging.INFO,
    )
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def fetch_running_config(
    host: str, port: int, username: str, password: str, timeout: int
) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        LOG.debug("Connecting to %s:%d", host, port)
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell(width=250, height=50)
        time.sleep(1.0)
        shell.recv(65535)

        shell.send("terminal length 0\n")
        time.sleep(0.5)
        shell.recv(65535)

        shell.send("show running-config\n")
        time.sleep(3.0)

        chunks: list[bytes] = []
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if shell.recv_ready():
                chunks.append(shell.recv(65535))
                deadline = time.monotonic() + 2
            else:
                time.sleep(0.2)

        shell.close()
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        client.close()


def normalize(raw: str) -> list[str]:
    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(p) for p in _VOLATILE_PREFIXES):
            continue
        if stripped == "!" or not stripped:
            continue
        lines.append(line.rstrip())
    return lines


def build_diff(
    baseline_lines: list[str], running_lines: list[str], device: str
) -> dict:
    unified = list(
        difflib.unified_diff(
            baseline_lines,
            running_lines,
            fromfile="baseline",
            tofile=f"{device} running-config",
            lineterm="",
        )
    )
    added = [l[1:] for l in unified if l.startswith("+") and not l.startswith("+++")]
    removed = [l[1:] for l in unified if l.startswith("-") and not l.startswith("---")]
    return {
        "device": device,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "drift_detected": bool(unified),
        "lines_added": len(added),
        "lines_removed": len(removed),
        "unified_diff": unified,
        "added": added,
        "removed": removed,
    }


def print_report(result: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result, indent=2))
        return

    if not result["drift_detected"]:
        LOG.info("No drift — running config matches baseline.")
        return

    header = (
        f"\n{'=' * 62}\n"
        f"DRIFT on {result['device']}  [{result['timestamp']}]\n"
        f"+{result['lines_added']} lines added  "
        f"-{result['lines_removed']} lines removed\n"
        f"{'=' * 62}\n"
    )
    print(header)

    if fmt == "unified":
        for line in result["unified_diff"]:
            print(line)
    else:
        if result["removed"]:
            print("REMOVED (in baseline, missing from device):")
            for ln in result["removed"]:
                print(f"  - {ln}")
        if result["added"]:
            print("\nADDED (on device, not in baseline):")
            for ln in result["added"]:
                print(f"  + {ln}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Diff a device running-config against a local golden baseline."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "-b", "--baseline", required=True, help="Path to golden baseline config file"
    )
    p.add_argument(
        "--format",
        choices=["unified", "summary", "json"],
        default="unified",
        help="Output format (default: unified)",
    )
    p.add_argument(
        "--save-running",
        metavar="PATH",
        help="Write fetched running-config to file before diffing",
    )
    p.add_argument(
        "--timeout", type=int, default=30, help="SSH connection timeout in seconds"
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        LOG.error("Baseline file not found: %s", baseline_path)
        return 1

    password = args.password or getpass(f"Password for {args.username}@{args.host}: ")

    LOG.info("Fetching running-config from %s", args.host)
    try:
        raw = fetch_running_config(
            args.host, args.port, args.username, password, args.timeout
        )
    except paramiko.AuthenticationException:
        LOG.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        LOG.error("Connection failed: %s", exc)
        return 1

    if args.save_running:
        Path(args.save_running).write_text(raw)
        LOG.info("Running config saved to %s", args.save_running)

    result = build_diff(
        normalize(baseline_path.read_text()),
        normalize(raw),
        args.host,
    )
    print_report(result, args.format)
    return 1 if result["drift_detected"] else 0


if __name__ == "__main__":
    sys.exit(main())