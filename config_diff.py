```python
#!/usr/bin/env python3
"""
config_diff.py - Network Device Configuration Diff Tool

Purpose:
    Compare the running configuration of a network device against a saved
    baseline or a previous backup, highlighting configuration drift.

Usage:
    python config_diff.py -d 192.168.1.1 -u admin -b backups/baseline.cfg
    python config_diff.py -d 192.168.1.1 -u admin -p secret --save-running
    python config_diff.py -d 192.168.1.1 -u admin -b baseline.cfg --output diff.txt

Prerequisites:
    - Python 3.8+
    - paramiko: pip install paramiko
    - Network device accessible via SSH
    - User account with privilege to run 'show running-config'
"""

import argparse
import difflib
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def get_running_config(hostname: str, username: str, password: str, port: int = 22) -> str:
    """SSH into device and retrieve running configuration."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log.info("Connecting to %s:%d as %s", hostname, port, username)
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )

        shell = client.invoke_shell(width=200, height=200)
        shell.settimeout(20)

        # Disable pagination
        for cmd in ("terminal length 0\n", "terminal width 0\n"):
            shell.send(cmd)
            _drain(shell)

        shell.send("show running-config\n")
        output = _read_until_prompt(shell)

        log.info("Retrieved running config (%d bytes)", len(output))
        return _strip_banner(output)

    finally:
        client.close()


def _drain(shell: paramiko.Channel, timeout: float = 1.0) -> None:
    """Discard buffered output after sending a command."""
    import time
    time.sleep(timeout)
    while shell.recv_ready():
        shell.recv(4096)


def _read_until_prompt(shell: paramiko.Channel, max_bytes: int = 524288) -> str:
    """Read shell output until a CLI prompt is detected."""
    import time
    buf = ""
    prompt_re = re.compile(r"[>#]\s*$", re.MULTILINE)
    deadline = time.time() + 60

    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(4096).decode("utf-8", errors="replace")
            buf += chunk
            if prompt_re.search(buf):
                # Consume any remaining data
                time.sleep(0.5)
                while shell.recv_ready():
                    buf += shell.recv(4096).decode("utf-8", errors="replace")
                break
        else:
            time.sleep(0.2)

    return buf


def _strip_banner(raw: str) -> str:
    """Remove SSH terminal noise; keep only config lines."""
    lines = raw.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if line.startswith("Building configuration") or line.startswith("Current configuration"):
            start = i
            break
    # Drop the last prompt line
    config_lines = lines[start:]
    while config_lines and re.match(r".*[>#]\s*$", config_lines[-1]):
        config_lines.pop()
    return "\n".join(config_lines)


def load_baseline(path: str) -> str:
    """Read a saved configuration file from disk."""
    p = Path(path)
    if not p.exists():
        log.error("Baseline file not found: %s", path)
        sys.exit(1)
    log.info("Loaded baseline from %s (%d bytes)", p, p.stat().st_size)
    return p.read_text(encoding="utf-8")


def save_config(config: str, path: str) -> None:
    """Write a configuration string to disk."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(config, encoding="utf-8")
    log.info("Saved running config to %s", p)


def generate_diff(baseline: str, running: str, device: str) -> str:
    """Produce a unified diff between baseline and running configs."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    diff = difflib.unified_diff(
        baseline.splitlines(keepends=True),
        running.splitlines(keepends=True),
        fromfile=f"baseline",
        tofile=f"{device} (running) @ {timestamp}",
        lineterm="",
    )
    return "".join(diff)


def summarize_diff(diff_text: str) -> dict:
    """Count added/removed lines for a quick summary."""
    added = sum(1 for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_text.splitlines() if l.startswith("-") and not l.startswith("---"))
    return {"added": added, "removed": removed}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare network device running config against a saved baseline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-b", "--baseline", help="Path to baseline config file to diff against")
    parser.add_argument(
        "--save-running",
        metavar="FILE",
        help="Save the retrieved running config to FILE instead of diffing",
    )
    parser.add_argument("-o", "--output", help="Write diff output to FILE (default: stdout)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if args.password is None:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        running = get_running_config(args.device, args.username, args.password, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    if args.save_running:
        save_config(running, args.save_running)
        sys.exit(0)

    if not args.baseline:
        log.error("Provide --baseline FILE or --save-running FILE")
        sys.exit(1)

    baseline = load_baseline(args.baseline)
    diff = generate_diff(baseline, running, args.device)

    if not diff:
        log.info("No differences found — running config matches baseline.")
        sys.exit(0)

    stats = summarize_diff(diff)
    log.info("Diff: +%d lines added, -%d lines removed", stats["added"], stats["removed"])

    if args.output:
        Path(args.output).write_text(diff, encoding="utf-8")
        log.info("Diff written to %s", args.output)
    else:
        print(diff)
```