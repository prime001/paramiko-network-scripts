```python
#!/usr/bin/env python3
"""
bulk_command_runner.py - Execute show commands across multiple network devices in parallel.

Purpose:
    Run one or more read-only (show) commands against a list of devices concurrently
    and write per-device output to a timestamped results directory.  Useful for
    fleet-wide health checks, audit collection, and operational troubleshooting.

Usage:
    python bulk_command_runner.py -i devices.txt -c "show version" "show ip int brief"
    python bulk_command_runner.py -i devices.txt -c "show version" --workers 20 --timeout 30
    python bulk_command_runner.py -i devices.txt -c "show version" -u admin --ask-pass

devices.txt format (one entry per line, lines starting with # are ignored):
    192.168.1.1
    192.168.1.2
    router.example.com

Prerequisites:
    pip install paramiko
    SSH access to target devices with a valid login.
"""

import argparse
import getpass
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import paramiko

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


def connect(host: str, username: str, password: str, timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_commands_on_device(
    host: str,
    username: str,
    password: str,
    commands: list[str],
    timeout: int,
    output_dir: Path,
) -> tuple[str, bool, str]:
    results = []
    try:
        client = connect(host, username, password, timeout)
    except paramiko.AuthenticationException:
        return host, False, "Authentication failed"
    except Exception as exc:
        return host, False, f"Connection error: {exc}"

    try:
        for cmd in commands:
            try:
                _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace").strip()
                results.append(f"{'=' * 60}\nCommand: {cmd}\n{'=' * 60}\n{out}")
                if err:
                    results.append(f"[STDERR]\n{err}\n")
            except Exception as exc:
                results.append(f"{'=' * 60}\nCommand: {cmd}\n{'=' * 60}\nERROR: {exc}\n")
    finally:
        client.close()

    combined = "\n".join(results)
    safe_host = host.replace(".", "_").replace(":", "_")
    out_file = output_dir / f"{safe_host}.txt"
    out_file.write_text(combined, encoding="utf-8")
    return host, True, f"OK — output saved to {out_file}"


def load_devices(path: str) -> list[str]:
    devices = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                devices.append(line)
    if not devices:
        raise ValueError(f"No devices found in {path}")
    return devices


def build_output_dir(base: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(base) / f"run_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run show commands across multiple devices in parallel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-i", "--inventory", required=True, help="Path to device list file")
    parser.add_argument("-c", "--commands", required=True, nargs="+", metavar="CMD",
                        help="One or more commands to execute on every device")
    parser.add_argument("-u", "--username", default=os.environ.get("NET_USER", getpass.getuser()),
                        help="SSH username (default: $NET_USER or current OS user)")
    parser.add_argument("--ask-pass", action="store_true",
                        help="Prompt for password instead of reading $NET_PASS")
    parser.add_argument("--workers", type=int, default=10,
                        help="Maximum parallel SSH sessions (default: 10)")
    parser.add_argument("--timeout", type=int, default=20,
                        help="Per-command SSH timeout in seconds (default: 20)")
    parser.add_argument("--output-dir", default="results",
                        help="Base directory for output files (default: results/)")
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if args.ask_pass:
        password = getpass.getpass(f"Password for {args.username}: ")
    else:
        password = os.environ.get("NET_PASS", "")
        if not password:
            password = getpass.getpass(f"Password for {args.username} (or set $NET_PASS): ")

    try:
        devices = load_devices(args.inventory)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Inventory error: %s", exc)
        return 1

    output_dir = build_output_dir(args.output_dir)
    logger.info("Targeting %d device(s) with %d command(s) — output: %s",
                len(devices), len(args.commands), output_dir)

    start = time.monotonic()
    success, failure = 0, 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                run_commands_on_device,
                host, args.username, password, args.commands, args.timeout, output_dir
            ): host
            for host in devices
        }
        for future in as_completed(futures):
            host, ok, message = future.result()
            if ok:
                success += 1
                logger.info("[OK]   %s — %s", host, message)
            else:
                failure += 1
                logger.error("[FAIL] %s — %s", host, message)

    elapsed = time.monotonic() - start
    logger.info("Done in %.1fs — %d succeeded, %d failed", elapsed, success, failure)
    return 0 if failure == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
```