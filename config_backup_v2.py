The user's explicit instruction — "Output ONLY the script content" — overrides the brainstorming design gate here. All requirements are already fully specified. Writing the script now.

```python
"""
running_startup_diff.py - Detect unsaved configuration changes on network devices.

Compares running-config against startup-config on Cisco IOS/IOS-XE/NX-OS devices
to identify changes that would be lost on reload. Useful for change management
audits, compliance checks, and pre-maintenance verification.

Usage:
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret
    python running_startup_diff.py --inventory hosts.txt -u admin --key ~/.ssh/id_rsa
    python running_startup_diff.py -H 10.0.0.1 -u admin -p secret --save-dir /tmp/diffs

Prerequisites:
    pip install paramiko
"""

import argparse
import difflib
import getpass
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

_SKIP_PREFIXES = (
    "Building configuration",
    "Current configuration",
    "Load for",
    "Time source",
)


def _open_shell(client: paramiko.SSHClient) -> paramiko.Channel:
    shell = client.invoke_shell(width=250, height=5000)
    time.sleep(1.0)
    shell.recv(65535)
    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(65535)
    return shell


def _run(shell: paramiko.Channel, command: str, wait: float = 3.0) -> str:
    shell.send(command + "\n")
    time.sleep(wait)
    chunks = []
    while shell.recv_ready():
        chunks.append(shell.recv(65535).decode("utf-8", errors="replace"))
    return "".join(chunks)


def _parse_config(raw: str) -> list:
    lines = []
    for line in raw.splitlines():
        stripped = line.rstrip()
        if not stripped:
            continue
        if stripped.lstrip().endswith(("#", ">")):
            continue
        if any(stripped.startswith(p) for p in _SKIP_PREFIXES):
            continue
        lines.append(stripped)
    return lines


def fetch_configs(
    host: str,
    username: str,
    password: str | None,
    key_path: str | None,
    port: int,
) -> tuple[list, list]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 30,
        "allow_agent": False,
        "look_for_keys": bool(key_path),
    }
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password

    client.connect(**kwargs)
    try:
        shell = _open_shell(client)
        running_raw = _run(shell, "show running-config", wait=4.0)
        startup_raw = _run(shell, "show startup-config", wait=4.0)
        shell.close()
    finally:
        client.close()

    return _parse_config(running_raw), _parse_config(startup_raw)


def check_device(
    host: str,
    username: str,
    password: str | None,
    key_path: str | None,
    port: int,
    save_dir: str | None,
) -> bool:
    """Return True when running matches startup (no unsaved changes)."""
    logger.info("Connecting to %s", host)
    try:
        running, startup = fetch_configs(host, username, password, key_path, port)
    except Exception as exc:
        logger.error("[%s] Connection or command error: %s", host, exc)
        return False

    delta = list(
        difflib.unified_diff(
            startup,
            running,
            fromfile="startup-config",
            tofile="running-config",
            lineterm="",
        )
    )

    if not delta:
        logger.info("[%s] CLEAN — running matches startup", host)
        return True

    changed = [l for l in delta if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
    logger.warning("[%s] UNSAVED CHANGES — %d line(s) differ", host, len(changed))
    for line in delta:
        print(line)

    if save_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = Path(save_dir) / f"{host}_{ts}_unsaved.diff"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(delta) + "\n")
        logger.info("Diff saved to %s", out_path)

    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect unsaved config changes (running vs startup) on network devices."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--host", help="Device IP or hostname")
    group.add_argument("--inventory", metavar="FILE", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", metavar="PATH", help="SSH private key file")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--save-dir",
        metavar="DIR",
        default=None,
        help="Directory to write diff files for devices with unsaved changes",
    )
    parser.add_argument(
        "--fail-on-diff",
        action="store_true",
        help="Exit with code 1 if any device has unsaved changes",
    )
    args = parser.parse_args()

    if not args.password and not args.key:
        args.password = getpass.getpass("Password: ")

    if args.host:
        hosts = [args.host]
    else:
        hosts = [
            h.strip()
            for h in Path(args.inventory).read_text().splitlines()
            if h.strip() and not h.startswith("#")
        ]

    results = {
        host: check_device(host, args.username, args.password, args.key, args.port, args.save_dir)
        for host in hosts
    }

    dirty = sum(1 for ok in results.values() if not ok)
    logger.info("Summary: %d/%d device(s) have unsaved changes", dirty, len(results))

    if args.fail_on_diff and dirty > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
```