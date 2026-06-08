The file path needs to be outside `/opt/NetAutoCommitter` since the user asked for a script for a different repo (`paramiko-network-scripts`). The output should just be the script content printed directly — they said "Output ONLY the script content, no markdown fences, no explanation."

"""
config_drift_detector.py - Detect configuration drift against a golden baseline.

Fetches the running config from a network device via SSH and compares it to a
locally stored baseline file, producing a unified diff. Useful for compliance
checks, change audits, and catching unauthorized modifications.

Usage:
    python config_drift_detector.py -H 192.168.1.1 -u admin -b baseline.cfg
    python config_drift_detector.py -H 192.168.1.1 -u admin -b baseline.cfg --save
    python config_drift_detector.py -H 192.168.1.1 -u admin -b baseline.cfg --section "ip access"

Prerequisites:
    pip install paramiko
    A baseline config file created from a known-good device state.
"""

import argparse
import difflib
import getpass
import logging
import re
import sys
from pathlib import Path

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def fetch_running_config(host: str, port: int, username: str, password: str, timeout: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, timeout=timeout)
        _, stdout, stderr = client.exec_command("show running-config", timeout=timeout)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.warning("stderr from device: %s", err)
        if not output.strip():
            raise RuntimeError("Empty response from device — check credentials and command support")
        return output
    finally:
        client.close()


def normalize(config: str) -> list[str]:
    """Strip timestamps, nonces, and trailing whitespace that produce false diffs."""
    noise = re.compile(
        r"^(! Last configuration change|! NVRAM config|Building configuration|"
        r"Current configuration|ntp clock-period|crypto pki certificate chain)",
        re.IGNORECASE,
    )
    lines = []
    for line in config.splitlines():
        stripped = line.rstrip()
        if noise.match(stripped):
            continue
        lines.append(stripped)
    return lines


def filter_section(lines: list[str], keyword: str) -> list[str]:
    """Return only blocks whose header line contains keyword."""
    result, in_block = [], False
    for line in lines:
        if line and not line.startswith(" ") and not line.startswith("!"):
            in_block = keyword.lower() in line.lower()
        if in_block:
            result.append(line)
    return result


def compute_diff(baseline: list[str], current: list[str], label_a: str, label_b: str) -> list[str]:
    return list(
        difflib.unified_diff(
            baseline,
            current,
            fromfile=label_a,
            tofile=label_b,
            lineterm="",
        )
    )


def load_baseline(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    return path.read_text(errors="replace")


def save_baseline(path: Path, config: str) -> None:
    path.write_text(config)
    log.info("Baseline saved to %s", path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Detect configuration drift against a golden baseline config."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("-b", "--baseline", required=True, help="Path to baseline config file")
    p.add_argument("--section", help="Filter diff to config blocks containing this keyword")
    p.add_argument("--save", action="store_true", help="Overwrite baseline with current config")
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds (default: 30)")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress info logs; only print diff")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.quiet:
        log.setLevel(logging.WARNING)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")
    baseline_path = Path(args.baseline)

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        current_raw = fetch_running_config(
            args.host, args.port, args.username, password, args.timeout
        )
    except (paramiko.AuthenticationException, paramiko.SSHException) as exc:
        log.error("SSH error: %s", exc)
        return 1
    except OSError as exc:
        log.error("Connection failed: %s", exc)
        return 1

    if args.save:
        save_baseline(baseline_path, current_raw)
        log.info("Baseline updated. No diff produced.")
        return 0

    try:
        baseline_raw = load_baseline(baseline_path)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1

    baseline_lines = normalize(baseline_raw)
    current_lines = normalize(current_raw)

    if args.section:
        baseline_lines = filter_section(baseline_lines, args.section)
        current_lines = filter_section(current_lines, args.section)
        log.info("Filtered to section keyword: %r", args.section)

    diff = compute_diff(
        baseline_lines,
        current_lines,
        label_a=f"baseline:{baseline_path.name}",
        label_b=f"live:{args.host}",
    )

    if not diff:
        log.info("No drift detected — running config matches baseline.")
        return 0

    changed = sum(1 for line in diff if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
    log.info("Drift detected (%d changed lines)", changed)
    print("\n".join(diff))
    return 2


if __name__ == "__main__":
    sys.exit(main())