config_drift_detector.py — Compare a device's running configuration against a
stored golden/baseline file to detect unauthorized or unintended config drift.

Unlike config_diff.py (running vs. startup) or config_diff_v2.py (two devices),
this script compares live device state against a known-good local reference,
making it suitable for compliance checks, change audits, and CI pipelines.

Usage:
    python config_drift_detector.py -d 192.168.1.1 -u admin -p secret \
        --baseline ./baselines/core-sw01.txt

    python config_drift_detector.py -d 10.0.0.1 -u admin -p secret \
        --baseline ./baselines/router01.txt \
        --ignore "^! Last config" "^! NVRAM" "^ntp clock-period" \
        --output drift_report.txt

Prerequisites:
    pip install paramiko
    Baseline files are plain-text Cisco IOS "show running-config" output.

Exit codes:
    0  Configuration matches baseline (no drift)
    1  Drift detected
    2  Connection, authentication, or file error
"""

import argparse
import difflib
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

RECV_TIMEOUT = 30
RECV_CHUNK = 4096


def fetch_running_config(host, port, username, password, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(2)
    except Exception as exc:
        log.error("Connection to %s failed: %s", host, exc)
        sys.exit(2)

    shell = client.invoke_shell(width=512, height=512)
    shell.settimeout(RECV_TIMEOUT)

    def send_and_wait(cmd, wait=1.5):
        shell.send(cmd + "\n")
        time.sleep(wait)
        output = b""
        while shell.recv_ready():
            output += shell.recv(RECV_CHUNK)
        return output.decode("utf-8", errors="replace")

    send_and_wait("terminal length 0", wait=1.0)
    raw = send_and_wait("show running-config", wait=3.0)
    client.close()

    lines = raw.splitlines()
    # Drop the echoed command and trailing prompt line
    start = next((i for i, l in enumerate(lines) if "show running-config" in l), -1)
    if start != -1:
        lines = lines[start + 1:]
    # Drop the final prompt line (ends with # or >)
    while lines and re.search(r"[#>]\s*$", lines[-1]):
        lines.pop()
    return lines


def load_baseline(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().splitlines()
    except OSError as exc:
        log.error("Cannot open baseline file: %s", exc)
        sys.exit(2)


def filter_lines(lines, patterns):
    if not patterns:
        return lines
    compiled = [re.compile(p) for p in patterns]
    return [l for l in lines if not any(rx.search(l) for rx in compiled)]


def build_diff(baseline, running, fromfile, tofile):
    return list(
        difflib.unified_diff(
            baseline,
            running,
            fromfile=f"baseline:{fromfile}",
            tofile=f"running:{tofile}",
            lineterm="",
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="Detect configuration drift against a golden baseline file."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout seconds")
    parser.add_argument("--baseline", required=True, metavar="FILE",
                        help="Path to golden/baseline config file")
    parser.add_argument("--ignore", nargs="*", metavar="REGEX", default=[],
                        help="Regex patterns for lines to exclude from comparison")
    parser.add_argument("--output", metavar="FILE",
                        help="Write diff report to this file instead of stdout")
    args = parser.parse_args()

    log.info("Loading baseline from %s", args.baseline)
    baseline_lines = load_baseline(args.baseline)

    log.info("Fetching running config from %s", args.device)
    running_lines = fetch_running_config(
        args.device, args.port, args.username, args.password, args.timeout
    )

    if args.ignore:
        log.info("Applying %d ignore pattern(s)", len(args.ignore))
        baseline_lines = filter_lines(baseline_lines, args.ignore)
        running_lines = filter_lines(running_lines, args.ignore)

    diff = build_diff(baseline_lines, running_lines, args.baseline, args.device)

    if not diff:
        log.info("No drift detected — running config matches baseline.")
        sys.exit(0)

    report = "\n".join(diff)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
            log.warning("Drift detected. Report written to %s", args.output)
        except OSError as exc:
            log.error("Failed to write output file: %s", exc)
            print(report)
    else:
        print(report)

    log.warning("Drift detected on %s — %d diff line(s)", args.device, len(diff))
    sys.exit(1)


if __name__ == "__main__":
    main()