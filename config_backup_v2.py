config_change_sentinel.py - Detect unauthorized or accidental config drift.

Purpose:
    Fetches the running configuration from a network device via SSH and
    compares it against a saved baseline.  Reports clean when hashes match;
    exits non-zero and prints a change summary when drift is detected.
    On first run, or when --update-baseline is passed, the current config
    becomes the new baseline.

Usage:
    python config_change_sentinel.py -d 192.168.1.1 -u admin
    python config_change_sentinel.py -d 192.168.1.1 -u admin -p secret --verbose
    python config_change_sentinel.py -d 192.168.1.1 -u admin --update-baseline

Prerequisites:
    pip install paramiko
    SSH access to a Cisco IOS/IOS-XE (or compatible) device.
    Baseline files are stored in ./baselines/ by default.
"""

import argparse
import hashlib
import logging
import os
import sys
import time
from getpass import getpass

import paramiko

BASELINE_DIR = "baselines"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def fetch_running_config(hostname, username, password, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        channel = client.invoke_shell()
        time.sleep(1)
        channel.recv(4096)

        for cmd in ("terminal length 0\n", "show running-config\n"):
            channel.send(cmd)
            time.sleep(0.5 if "terminal" in cmd else 4)

        output = b""
        deadline = time.time() + 15
        while time.time() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(65535)
                output += chunk
                deadline = time.time() + 2
            else:
                time.sleep(0.1)

        return output.decode("utf-8", errors="replace")
    finally:
        client.close()


def config_hash(config_text):
    """SHA-256 of config with volatile timestamp lines stripped."""
    filtered = "\n".join(
        line for line in config_text.splitlines()
        if not line.startswith("! Last configuration change")
        and not line.startswith("! NVRAM config last updated")
    )
    return hashlib.sha256(filtered.encode()).hexdigest()


def baseline_path(hostname, baseline_dir):
    safe_name = hostname.replace(".", "_").replace(":", "_")
    return os.path.join(baseline_dir, f"{safe_name}.cfg")


def load_baseline(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        text = f.read()
    return text, config_hash(text)


def save_baseline(path, config_text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        f.write(config_text)
    logger.info("Baseline saved: %s", path)


def diff_summary(baseline_text, current_text):
    baseline_lines = set(baseline_text.splitlines())
    current_lines = set(current_text.splitlines())
    return current_lines - baseline_lines, baseline_lines - current_lines


def build_parser():
    p = argparse.ArgumentParser(
        description="Compare device running-config against a saved baseline."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    p.add_argument("--baseline-dir", default=BASELINE_DIR)
    p.add_argument("--baseline", help="Explicit baseline file path")
    p.add_argument(
        "--update-baseline",
        action="store_true",
        help="Overwrite baseline with current config and exit",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print individual added/removed lines",
    )
    return p


def main():
    args = build_parser().parse_args()
    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    logger.info("Connecting to %s", args.device)
    try:
        current = fetch_running_config(
            args.device, args.username, password,
            port=args.port, timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    bpath = args.baseline or baseline_path(args.device, args.baseline_dir)

    if args.update_baseline:
        save_baseline(bpath, current)
        print(f"Baseline updated: {bpath}")
        return

    result = load_baseline(bpath)
    if result is None:
        logger.warning("No baseline at %s — establishing one now.", bpath)
        save_baseline(bpath, current)
        print("First run: baseline established. Re-run to detect changes.")
        return

    baseline_text, baseline_hash = result
    current_hash = config_hash(current)

    if current_hash == baseline_hash:
        print(f"[OK] {args.device}: config matches baseline ({current_hash[:16]}...)")
        return

    added, removed = diff_summary(baseline_text, current)
    print(
        f"[DRIFT] {args.device}: configuration has changed!\n"
        f"  Lines added  : {len(added)}\n"
        f"  Lines removed: {len(removed)}\n"
        f"  Baseline hash: {baseline_hash[:16]}...\n"
        f"  Current hash : {current_hash[:16]}..."
    )

    if args.verbose:
        if added:
            print("\nAdded:")
            for line in sorted(added):
                print(f"  + {line}")
        if removed:
            print("\nRemoved:")
            for line in sorted(removed):
                print(f"  - {line}")

    sys.exit(2)


if __name__ == "__main__":
    main()