```python
"""
config_diff.py - Network Device Configuration Drift Detector

Connects to a Cisco IOS/IOS-XE device via SSH, retrieves the running
configuration, and compares it against a local baseline file using
unified diff format. Useful for detecting unauthorized changes, auditing
drift after maintenance windows, and validating configuration compliance.

Usage:
    python config_diff.py -d 192.168.1.1 -u admin -b ./baselines/router1.cfg
    python config_diff.py -d 192.168.1.1 -u admin -b ./baselines/router1.cfg --save
    python config_diff.py -d 192.168.1.1 -u admin -b ./baselines/router1.cfg --context 5

Prerequisites:
    pip install paramiko
    Baseline file must exist (create one with config_backup.py first)

Environment variables:
    NET_PASSWORD  - SSH password (if not using -p flag)
    NET_ENABLE    - Enable secret (if required)
"""

import argparse
import difflib
import logging
import os
import sys
import time
from datetime import datetime
from getpass import getpass
from pathlib import Path

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def get_running_config(host, username, password, enable_secret=None,
                       port=22, timeout=30):
    """SSH into device and retrieve the running configuration."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log.info("Connecting to %s:%d", host, port)
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )

        shell = client.invoke_shell(width=220, height=50)
        time.sleep(1)
        shell.recv(65535)  # drain banner/MOTD

        if enable_secret:
            shell.send("enable\n")
            time.sleep(0.5)
            shell.send(enable_secret + "\n")
            time.sleep(0.5)
            shell.recv(65535)

        shell.send("terminal length 0\n")
        time.sleep(0.5)
        shell.recv(65535)

        shell.send("show running-config\n")
        time.sleep(3)

        output = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if shell.recv_ready():
                chunk = shell.recv(65535)
                output += chunk
                if output.rstrip().endswith(b"#"):
                    break
            else:
                time.sleep(0.2)

        config_text = output.decode("utf-8", errors="replace")

        # Strip the command echo and prompt lines
        lines = config_text.splitlines()
        config_lines = []
        in_config = False
        for line in lines:
            if line.strip().startswith("Building configuration"):
                in_config = True
            if in_config:
                if line.strip().endswith("#") and not line.strip().startswith("!"):
                    break
                config_lines.append(line.rstrip())

        return "\n".join(config_lines)

    finally:
        client.close()


def load_baseline(path):
    """Load baseline configuration from a local file."""
    baseline_path = Path(path)
    if not baseline_path.exists():
        raise FileNotFoundError(
            f"Baseline file not found: {path}\n"
            "Create one first with config_backup.py"
        )
    return baseline_path.read_text(encoding="utf-8")


def save_baseline(path, content):
    """Overwrite baseline file with current running config."""
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(content, encoding="utf-8")
    log.info("Baseline updated: %s", path)


def compute_diff(baseline, current, host, context_lines=3):
    """Return unified diff between baseline and current config."""
    baseline_lines = baseline.splitlines(keepends=True)
    current_lines = current.splitlines(keepends=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    diff = difflib.unified_diff(
        baseline_lines,
        current_lines,
        fromfile="baseline",
        tofile=f"{host} running-config ({timestamp})",
        n=context_lines,
    )
    return "".join(diff)


def print_diff_summary(diff_text):
    """Print colored diff output if terminal supports it, else plain."""
    supports_color = sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"

    if not diff_text:
        log.info("No differences found — configuration matches baseline.")
        return 0

    added = sum(1 for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_text.splitlines() if l.startswith("-") and not l.startswith("---"))
    log.warning("Drift detected: +%d lines added, -%d lines removed", added, removed)

    for line in diff_text.splitlines():
        if supports_color:
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

    return 1


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect configuration drift between a device and a baseline file."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None,
                        help="SSH password (prompted if omitted; or set NET_PASSWORD)")
    parser.add_argument("-e", "--enable", default=None,
                        help="Enable secret (or set NET_ENABLE)")
    parser.add_argument("-b", "--baseline", required=True,
                        help="Path to baseline configuration file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="SSH connection timeout in seconds (default: 30)")
    parser.add_argument("--context", type=int, default=3,
                        help="Context lines around diff hunks (default: 3)")
    parser.add_argument("--save", action="store_true",
                        help="Update baseline with current config after comparison")
    parser.add_argument("--output", default=None,
                        help="Write diff to file instead of (or in addition to) stdout")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress diff output; exit code indicates drift")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    password = (
        args.password
        or os.environ.get("NET_PASSWORD")
        or getpass(f"Password for {args.username}@{args.device}: ")
    )
    enable_secret = args.enable or os.environ.get("NET_ENABLE")

    try:
        baseline = load_baseline(args.baseline)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        sys.exit(2)

    try:
        current = get_running_config(
            host=args.device,
            username=args.username,
            password=password,
            enable_secret=enable_secret,
            port=args.port,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(2)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(2)

    diff = compute_diff(baseline, current, args.device, context_lines=args.context)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(diff if diff else "(no differences)\n", encoding="utf-8")
        log.info("Diff written to %s", args.output)

    if not args.quiet:
        exit_code = print_diff_summary(diff)
    else:
        exit_code = 1 if diff else 0

    if args.save:
        if not diff:
            log.info("Baseline already matches running config — no update needed.")
        else:
            save_baseline(args.baseline, current)

    sys.exit(exit_code)
```