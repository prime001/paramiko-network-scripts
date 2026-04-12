```python
"""
bulk_command_runner.py — Run commands across multiple network devices concurrently.

Purpose:
    Execute one or more show/exec commands against a fleet of devices in parallel,
    collecting structured output to stdout or a JSON/CSV file. Useful for audits,
    health checks, and ad-hoc investigations across large inventories.

Usage:
    # Single device, commands inline
    python bulk_command_runner.py -H 192.168.1.1 -u admin -c "show version" "show ip int br"

    # Fleet from file, commands from file, JSON output
    python bulk_command_runner.py --hosts hosts.txt --commands cmds.txt \
        -u admin --password --output results.json --workers 20

Prerequisites:
    pip install paramiko
    hosts.txt: one IP or hostname per line (# lines ignored)
    cmds.txt:  one command per line (# lines ignored)
"""

import argparse
import csv
import getpass
import json
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import paramiko

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)
log = logging.getLogger(__name__)


def ssh_run_commands(host, port, username, password, commands, timeout):
    """Open an SSH session to *host* and run each command sequentially."""
    results = []
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
        for cmd in commands:
            try:
                _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                output = stdout.read().decode(errors="replace").strip()
                error = stderr.read().decode(errors="replace").strip()
                results.append(
                    {
                        "command": cmd,
                        "output": output,
                        "error": error,
                        "status": "ok" if not error else "warn",
                    }
                )
            except Exception as exc:
                results.append(
                    {"command": cmd, "output": "", "error": str(exc), "status": "error"}
                )
    except (paramiko.AuthenticationException,) as exc:
        results.append(
            {"command": "<connect>", "output": "", "error": f"Auth failed: {exc}", "status": "error"}
        )
    except (socket.timeout, paramiko.SSHException, OSError) as exc:
        results.append(
            {"command": "<connect>", "output": "", "error": str(exc), "status": "error"}
        )
    finally:
        client.close()
    return results


def run_on_host(host, port, username, password, commands, timeout):
    """Wrapper that returns a result dict keyed by host."""
    log.info("Connecting to %s", host)
    start = time.monotonic()
    cmd_results = ssh_run_commands(host, port, username, password, commands, timeout)
    elapsed = round(time.monotonic() - start, 2)
    overall = "error" if any(r["status"] == "error" for r in cmd_results) else "ok"
    log.info("Finished %s in %.2fs — %s", host, elapsed, overall)
    return {
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": elapsed,
        "status": overall,
        "commands": cmd_results,
    }


def load_lines(path):
    """Read non-blank, non-comment lines from *path*."""
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def write_output(records, path):
    """Write results to *path* (JSON) or stdout (pretty JSON)."""
    payload = json.dumps(records, indent=2)
    if path:
        with open(path, "w") as fh:
            fh.write(payload)
        log.info("Results written to %s", path)
    else:
        print(payload)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run commands across multiple network devices in parallel."
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("-H", "--host", metavar="HOST", nargs="+", help="One or more device IPs/hostnames")
    host_group.add_argument("--hosts", metavar="FILE", help="File with one host per line")

    cmd_group = parser.add_mutually_exclusive_group(required=True)
    cmd_group.add_argument("-c", "--commands", metavar="CMD", nargs="+", help="Commands to run")
    cmd_group.add_argument("--commands-file", metavar="FILE", help="File with one command per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument(
        "-p", "--password", dest="password_flag", action="store_true",
        help="Prompt for password (omit to use SSH agent/key)"
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-command timeout in seconds (default: 15)")
    parser.add_argument("--workers", type=int, default=10, help="Max parallel SSH sessions (default: 10)")
    parser.add_argument("--output", metavar="FILE", help="Write JSON results to FILE (default: stdout)")
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()

    hosts = args.host if args.host else load_lines(args.hosts)
    commands = args.commands if args.commands else load_lines(args.commands_file)

    if not hosts:
        log.error("No hosts specified.")
        sys.exit(1)
    if not commands:
        log.error("No commands specified.")
        sys.exit(1)

    password = getpass.getpass(f"Password for {args.username}: ") if args.password_flag else None

    log.info(
        "Running %d command(s) on %d device(s) with %d workers",
        len(commands), len(hosts), args.workers,
    )

    records = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                run_on_host, h, args.port, args.username, password, commands, args.timeout
            ): h
            for h in hosts
        }
        for fut in as_completed(futures):
            try:
                records.append(fut.result())
            except Exception as exc:
                host = futures[fut]
                log.error("Unexpected error for %s: %s", host, exc)
                records.append({"host": host, "status": "error", "error": str(exc)})

    records.sort(key=lambda r: r["host"])
    write_output(records, args.output)

    errors = sum(1 for r in records if r.get("status") == "error")
    log.info("Done. %d/%d hosts had errors.", errors, len(records))
    sys.exit(1 if errors else 0)
```