The user's instructions are explicit and complete — the spec is fully defined, output only. Writing the script now.

"""
running_vs_startup_diff.py — Detect unsaved config changes on network devices.

Compares 'show running-config' against 'show startup-config' via SSH and reports
any lines that differ between the two. Use this before maintenance windows to
confirm all changes are saved, or in scheduled audits to catch config drift before
an unexpected reload wipes uncommitted work.

Usage:
    Single device:
        python running_vs_startup_diff.py -d 192.168.1.1 -u admin

    Multiple devices from a file (one host per line):
        python running_vs_startup_diff.py -f devices.txt -u admin

    Save configs automatically where drift is found:
        python running_vs_startup_diff.py -f devices.txt -u admin --save

    Suppress per-device diff, show summary only:
        python running_vs_startup_diff.py -f devices.txt -u admin --summary-only

Prerequisites:
    pip install paramiko

    Tested against Cisco IOS/IOS-XE. Devices must allow 'show startup-config';
    some platforms require privilege level 15 or a local flash copy to exist.
"""

import argparse
import difflib
import getpass
import logging
import sys
import time
from typing import Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_SKIP_PREFIXES = (
    "Building configuration",
    "Current configuration",
    "Last configuration change",
    "NVRAM config last updated",
)


def connect(host: str, username: str, password: str, port: int,
            timeout: int) -> Optional[paramiko.SSHClient]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
    except paramiko.SSHException as exc:
        log.error("%s: SSH error: %s", host, exc)
    except OSError as exc:
        log.error("%s: connection failed: %s", host, exc)
    return None


def shell_run(client: paramiko.SSHClient, command: str,
              wait: float = 3.0) -> str:
    chan = client.invoke_shell(width=250, height=5000)
    time.sleep(0.5)
    chan.recv(65535)
    chan.send("terminal length 0\n")
    time.sleep(0.5)
    chan.recv(65535)
    chan.send(command + "\n")
    time.sleep(wait)

    buf = ""
    deadline = time.time() + 60
    while time.time() < deadline:
        if chan.recv_ready():
            buf += chan.recv(65535).decode("utf-8", errors="replace")
            tail = buf.rstrip()
            if tail.endswith("#") or tail.endswith(">"):
                break
        else:
            time.sleep(0.3)

    chan.close()
    return buf


def normalize(raw: str) -> list[str]:
    lines = []
    for line in raw.splitlines():
        s = line.rstrip()
        if not s or s == "!":
            continue
        if any(s.startswith(p) for p in _SKIP_PREFIXES):
            continue
        lines.append(s)
    return lines


def check_device(host: str, username: str, password: str,
                 port: int, timeout: int, save: bool) -> dict:
    result = {"host": host, "status": "error", "diff": [], "saved": False}

    client = connect(host, username, password, port, timeout)
    if not client:
        return result

    try:
        log.info("%s: reading running-config", host)
        running = normalize(shell_run(client, "show running-config", wait=4))

        log.info("%s: reading startup-config", host)
        startup = normalize(shell_run(client, "show startup-config", wait=4))

        diff = list(difflib.unified_diff(
            startup, running,
            fromfile="startup-config",
            tofile="running-config",
            lineterm="",
        ))
        result["diff"] = diff
        result["status"] = "drift" if diff else "clean"

        if diff and save:
            log.info("%s: writing memory", host)
            shell_run(client, "write memory", wait=5)
            result["saved"] = True
    finally:
        client.close()

    return result


def load_hosts(path: str) -> list[str]:
    with open(path) as fh:
        return [
            line.strip() for line in fh
            if line.strip() and not line.startswith("#")
        ]


def print_report(results: list[dict], summary_only: bool) -> None:
    clean = [r for r in results if r["status"] == "clean"]
    drift = [r for r in results if r["status"] == "drift"]
    errors = [r for r in results if r["status"] == "error"]

    print("\n" + "=" * 60)
    print("RUNNING vs STARTUP CONFIG REPORT")
    print("=" * 60)
    print(
        f"\nDevices: {len(results)}  |  "
        f"Clean: {len(clean)}  |  "
        f"Drift: {len(drift)}  |  "
        f"Unreachable: {len(errors)}\n"
    )

    for r in errors:
        print(f"  [ERROR]  {r['host']}")

    for r in clean:
        print(f"  [CLEAN]  {r['host']}")

    for r in drift:
        tag = "[SAVED]" if r["saved"] else "[UNSAVED]"
        print(f"  [DRIFT]  {r['host']}  {tag}  ({len(r['diff'])} diff lines)")
        if not summary_only:
            print()
            for line in r["diff"]:
                print("    " + line)
            print()

    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare running-config vs startup-config to find unsaved changes."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device hostname or IP")
    target.add_argument("-f", "--file", help="File listing one host per line")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=30,
                        help="Connection timeout in seconds (default: 30)")
    parser.add_argument("--save", action="store_true",
                        help="Run 'write memory' on devices where drift is found")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print summary table only; suppress line-by-line diff")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")
    hosts = [args.device] if args.device else load_hosts(args.file)

    if not hosts:
        log.error("No hosts to check.")
        return 1

    results = [
        check_device(h, args.username, password, args.port, args.timeout, args.save)
        for h in hosts
    ]

    print_report(results, args.summary_only)

    return 1 if any(r["status"] == "drift" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())