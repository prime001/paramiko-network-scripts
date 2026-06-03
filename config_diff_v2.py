The prompt says "Output ONLY the script content" — outputting directly:

```
"""
running_startup_diff.py — Detect unsaved configuration drift on network devices.

Compares 'show running-config' against 'show startup-config' to surface changes
that have not been written to NVRAM. Useful for pre-maintenance hygiene checks,
change-window audits, and compliance verification.

Usage:
    # Single device
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret

    # Multiple devices from a file (one IP/hostname per line, # for comments)
    python running_startup_diff.py --hosts devices.txt -u admin -p secret

    # Save report to file and exit non-zero if any drift found
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret \
        -o drift_report.txt --exit-nonzero

    # Use SSH key authentication
    python running_startup_diff.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa

Prerequisites:
    pip install paramiko
"""

import argparse
import difflib
import logging
import sys
import time
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def _drain(channel: paramiko.Channel, timeout: float = 30.0) -> str:
    """Read from channel until a prompt character appears or timeout."""
    buf = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            buf += channel.recv(65535).decode("utf-8", errors="replace")
            if buf.rstrip().endswith(("#", ">")):
                break
        else:
            time.sleep(0.05)
    return buf


def _send(channel: paramiko.Channel, cmd: str, timeout: float = 90.0) -> str:
    """Send a command and return output with echoed command and prompt stripped."""
    channel.send(cmd + "\n")
    raw = _drain(channel, timeout)
    lines = raw.splitlines()
    if lines and cmd.strip() in lines[0]:
        lines = lines[1:]
    if lines and lines[-1].strip().endswith(("#", ">")):
        lines = lines[:-1]
    return "\n".join(lines)


def fetch_configs(
    host: str,
    username: str,
    password: str = None,
    key_path: str = None,
    port: int = 22,
) -> tuple[list[str], list[str]]:
    """Connect and return (running_lines, startup_lines)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw: dict = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 15,
        "look_for_keys": bool(key_path),
        "allow_agent": False,
    }
    if key_path:
        kw["key_filename"] = key_path
    else:
        kw["password"] = password

    client.connect(**kw)
    try:
        shell = client.invoke_shell(width=250, height=50000)
        time.sleep(1)
        _drain(shell, timeout=5)
        _send(shell, "terminal length 0")
        running = _send(shell, "show running-config").splitlines()
        startup = _send(shell, "show startup-config").splitlines()
    finally:
        client.close()

    return running, startup


def diff_configs(
    running: list[str], startup: list[str], host: str
) -> list[str]:
    return list(
        difflib.unified_diff(
            startup,
            running,
            fromfile=f"{host}:startup-config",
            tofile=f"{host}:running-config",
            lineterm="",
        )
    )


def check_device(
    host: str,
    username: str,
    password: str = None,
    key_path: str = None,
    port: int = 22,
) -> list[str]:
    log.info("Connecting to %s", host)
    try:
        running, startup = fetch_configs(host, username, password, key_path, port)
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
        return []
    except (paramiko.SSHException, OSError) as exc:
        log.error("%s: connection error — %s", host, exc)
        return []

    diff = diff_configs(running, startup, host)
    if diff:
        log.warning("%s: %d diff lines — unsaved changes detected", host, len(diff))
    else:
        log.info("%s: clean — running-config matches startup-config", host)
    return diff


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Detect unsaved config drift (running vs startup) on "
        "Cisco-style devices via SSH.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-H", "--host", help="Device IP or hostname")
    target.add_argument(
        "--hosts", metavar="FILE", help="File with one device per line"
    )
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", default=None)
    p.add_argument("--key", dest="key_path", default=None, help="SSH private key path")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("-o", "--output", metavar="FILE", help="Write report to file")
    p.add_argument(
        "--exit-nonzero",
        action="store_true",
        help="Exit with code 1 if drift is found on any device",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.host:
        hosts = [args.host]
    else:
        path = Path(args.hosts)
        if not path.exists():
            log.error("Hosts file not found: %s", args.hosts)
            return 1
        hosts = [
            ln.strip()
            for ln in path.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")
        ]

    drifted: dict[str, list[str]] = {}
    for host in hosts:
        diff = check_device(
            host,
            args.username,
            password=args.password,
            key_path=args.key_path,
            port=args.port,
        )
        if diff:
            drifted[host] = diff

    if not drifted:
        print("All devices: running-config matches startup-config. No drift found.")
        return 0

    sections = []
    for host, diff in drifted.items():
        sections.append("=" * 60)
        sections.append(f"DRIFT DETECTED: {host}")
        sections.append("=" * 60)
        sections.extend(diff)
        sections.append("")

    report = "\n".join(sections)

    if args.output:
        Path(args.output).write_text(report)
        log.info("Report written to %s", args.output)
    else:
        print(report)

    return 1 if args.exit_nonzero else 0


if __name__ == "__main__":
    sys.exit(main())
```