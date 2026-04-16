The user instruction "Output ONLY the script content" takes precedence over brainstorming. Writing the script now.

```python
#!/usr/bin/env python3
"""
bulk_command_runner.py — Parallel bulk command execution across network devices.

Purpose:
    Connect to multiple network devices concurrently and run a list of show
    commands on each one.  Results are written to per-device log files and a
    consolidated CSV summary, making it easy to audit fleet-wide state in one
    pass.

Usage:
    python bulk_command_runner.py \\
        --inventory devices.txt \\
        --commands commands.txt \\
        --username admin \\
        --output-dir ./results \\
        [--password]          # prompted if omitted \\
        [--threads 10]        # default: 5 \\
        [--timeout 30]        # SSH timeout in seconds \\
        [--port 22]

Inventory file format (one host per line, lines starting with # ignored):
    192.168.1.1
    192.168.1.2
    sw-core-01.example.com

Commands file format (one IOS/NX-OS show command per line):
    show version
    show ip interface brief
    show logging last 20

Prerequisites:
    pip install paramiko
"""

import argparse
import csv
import getpass
import logging
import os
import socket
import sys
import threading
from datetime import datetime
from pathlib import Path

import paramiko

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(threadName)s — %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger(__name__)

_results_lock = threading.Lock()


def load_lines(path: str) -> list[str]:
    """Return non-empty, non-comment lines from a text file."""
    lines = []
    with open(path) as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
    return lines


def run_commands_on_device(
    host: str,
    username: str,
    password: str,
    commands: list[str],
    output_dir: Path,
    port: int,
    timeout: int,
) -> dict:
    """SSH to *host*, run each command, return a result dict."""
    result = {
        "host": host,
        "status": "error",
        "commands_run": 0,
        "error": "",
    }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )

        device_file = output_dir / f"{host.replace('.', '_')}.txt"
        with open(device_file, "w") as out:
            out.write(f"# Device: {host}\n")
            out.write(f"# Captured: {datetime.utcnow().isoformat()}Z\n\n")

            for cmd in commands:
                out.write(f"{'=' * 60}\n")
                out.write(f"# {cmd}\n")
                out.write(f"{'=' * 60}\n")

                _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                output = stdout.read().decode(errors="replace")
                error_output = stderr.read().decode(errors="replace")

                out.write(output)
                if error_output.strip():
                    out.write(f"\n[STDERR] {error_output}")
                out.write("\n")

        result["status"] = "ok"
        result["commands_run"] = len(commands)
        log.info("%s — completed %d commands → %s", host, len(commands), device_file.name)

    except (paramiko.AuthenticationException,) as exc:
        result["error"] = f"auth error: {exc}"
        log.error("%s — %s", host, result["error"])
    except (paramiko.SSHException, socket.error, OSError) as exc:
        result["error"] = str(exc)
        log.error("%s — connection error: %s", host, exc)
    finally:
        client.close()

    return result


def worker(host, username, password, commands, output_dir, port, timeout, all_results):
    result = run_commands_on_device(
        host, username, password, commands, output_dir, port, timeout
    )
    with _results_lock:
        all_results.append(result)


def write_summary(results: list[dict], output_dir: Path) -> None:
    summary_path = output_dir / "summary.csv"
    fieldnames = ["host", "status", "commands_run", "error"]
    with open(summary_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    log.info("Summary written to %s", summary_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run show commands on multiple devices in parallel via SSH."
    )
    parser.add_argument("--inventory", required=True, help="File with one host per line")
    parser.add_argument("--commands", required=True, help="File with one command per line")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--output-dir", default="results", help="Directory for output files")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent SSH sessions")
    parser.add_argument("--timeout", type=int, default=30, help="SSH connect/exec timeout (s)")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    hosts = load_lines(args.inventory)
    commands = load_lines(args.commands)

    if not hosts:
        log.error("No hosts found in %s", args.inventory)
        sys.exit(1)
    if not commands:
        log.error("No commands found in %s", args.commands)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info(
        "Starting: %d hosts × %d commands using %d threads",
        len(hosts),
        len(commands),
        args.threads,
    )

    all_results: list[dict] = []
    semaphore = threading.Semaphore(args.threads)
    threads = []

    def throttled_worker(host):
        with semaphore:
            worker(host, password, commands, output_dir, args.port, args.timeout, all_results)

    # Fix closure over loop variable
    def make_target(h):
        def target():
            with semaphore:
                worker(h, args.username, password, commands, output_dir, args.port, args.timeout, all_results)
        return target

    for host in hosts:
        t = threading.Thread(target=make_target(host), name=host, daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    write_summary(all_results, output_dir)

    ok = sum(1 for r in all_results if r["status"] == "ok")
    failed = len(all_results) - ok
    print(f"\nDone: {ok} succeeded, {failed} failed. Results in: {output_dir}/")
    sys.exit(0 if failed == 0 else 1)
```