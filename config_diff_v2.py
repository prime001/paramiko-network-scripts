config_compliance_check.py - Network device compliance baseline checker

Fetches the running configuration from a Cisco IOS/IOS-XE device via SSH and
compares it against a local golden/baseline config file. Reports lines missing
from the device (compliance gaps) and lines present on the device but absent
from the baseline (configuration drift).

Usage:
    python config_compliance_check.py -d 192.168.1.1 -u admin -p secret \
        -b ./baselines/core-switch-baseline.txt

    # Read password from environment variable:
    NET_PASSWORD=secret python config_compliance_check.py \
        -d 192.168.1.1 -u admin -b ./baselines/core-switch-baseline.txt

    # Only report compliance gaps (missing from device):
    python config_compliance_check.py -d 192.168.1.1 -u admin \
        -b baseline.txt --gaps-only

Prerequisites:
    pip install paramiko
"""

import argparse
import logging
import os
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

CONNECT_TIMEOUT = 15
RECV_TIMEOUT = 30
RECV_BUFFER = 65535
PROMPT_WAIT = 2.0


def fetch_running_config(host, port, username, password):
    """SSH into device and return the full running-config output."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        log.info("Connecting to %s:%d", host, port)
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell(width=200)
        time.sleep(PROMPT_WAIT)
        shell.recv(RECV_BUFFER)

        shell.send("terminal length 0\n")
        time.sleep(0.5)
        shell.recv(RECV_BUFFER)

        shell.send("show running-config\n")
        time.sleep(PROMPT_WAIT)

        output = b""
        deadline = time.time() + RECV_TIMEOUT
        while time.time() < deadline:
            if shell.recv_ready():
                chunk = shell.recv(RECV_BUFFER)
                output += chunk
                if b"#" in chunk[-20:]:
                    break
            else:
                time.sleep(0.3)

        return output.decode("utf-8", errors="replace")
    finally:
        client.close()


def normalize_lines(text):
    """Return non-empty, stripped lines from config text, excluding banners/noise."""
    skip_prefixes = ("!", "Building configuration", "Current configuration", "end")
    result = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in skip_prefixes):
            continue
        result.add(stripped)
    return result


def load_baseline(path):
    """Load and normalize the golden baseline config file."""
    try:
        with open(path, encoding="utf-8") as fh:
            return normalize_lines(fh.read())
    except OSError as exc:
        log.error("Cannot read baseline file %s: %s", path, exc)
        sys.exit(1)


def run_compliance_check(host, port, username, password, baseline_path, gaps_only):
    """
    Compare device running-config against baseline.
    Returns exit code: 0=compliant, 1=drift found.
    """
    baseline = load_baseline(baseline_path)
    log.info("Baseline loaded: %d unique config lines from %s", len(baseline), baseline_path)

    raw = fetch_running_config(host, port, username, password)
    running = normalize_lines(raw)
    log.info("Device config fetched: %d unique config lines from %s", len(running), host)

    missing = sorted(baseline - running)
    extra = sorted(running - baseline)

    print("\n" + "=" * 60)
    print("Compliance Report: %s" % host)
    print("Baseline: %s" % baseline_path)
    print("=" * 60)

    if missing:
        print("\n[FAIL] Compliance gaps -- %d line(s) missing from device:" % len(missing))
        for line in missing:
            print("  - %s" % line)
    else:
        print("\n[PASS] No compliance gaps -- all baseline lines present on device.")

    if not gaps_only:
        if extra:
            print("\n[WARN] Configuration drift -- %d line(s) on device not in baseline:" % len(extra))
            for line in extra:
                print("  + %s" % line)
        else:
            print("\n[PASS] No configuration drift -- device has no extra lines beyond baseline.")

    print("\nSummary: %d gap(s), %d extra line(s)" % (len(missing), len(extra)))
    print("=" * 60)

    return 1 if missing or (not gaps_only and extra) else 0


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare device running-config against a compliance baseline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument(
        "-p", "--password",
        default=os.environ.get("NET_PASSWORD"),
        help="SSH password (or set NET_PASSWORD env var)",
    )
    parser.add_argument("-b", "--baseline", required=True, help="Path to golden baseline config file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--gaps-only",
        action="store_true",
        help="Only report missing lines; ignore lines on device not in baseline",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password:
        log.error("Password required: use -p or set NET_PASSWORD environment variable.")
        sys.exit(1)

    try:
        exit_code = run_compliance_check(
            host=args.device,
            port=args.port,
            username=args.username,
            password=args.password,
            baseline_path=args.baseline,
            gaps_only=args.gaps_only,
        )
        sys.exit(exit_code)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(2)
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", args.device, exc)
        sys.exit(2)
    except OSError as exc:
        log.error("Network error connecting to %s: %s", args.device, exc)
        sys.exit(2)