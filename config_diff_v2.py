This is a code generation task — the script goes to the user's GitHub portfolio repo, not this working directory. Outputting the script directly:

```
"""
running_startup_diff.py - Detect unsaved configuration changes on network devices.

Connects to one or more Cisco IOS/IOS-XE devices via SSH and diffs running-config
against startup-config to find changes that haven't been written to NVRAM. Useful
for auditing change-management compliance (every approved change should end with
'write memory') or pre-maintenance safety checks.

Usage:
    Single device:
        python running_startup_diff.py -d 192.168.1.1 -u admin -p secret

    Multiple devices from file (one IP/hostname per line):
        python running_startup_diff.py -f devices.txt -u admin

    Save report to file:
        python running_startup_diff.py -f devices.txt -u admin -o report.txt

Prerequisites:
    pip install paramiko
"""

import argparse
import difflib
import logging
import sys
import time
from getpass import getpass
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

SSH_TIMEOUT = 10
COMMAND_WAIT = 3.0


def ssh_connect(host: str, username: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=SSH_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def send_command(shell: paramiko.Channel, command: str, wait: float = COMMAND_WAIT) -> str:
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
    return output


def fetch_config(shell: paramiko.Channel, command: str) -> list[str]:
    raw = send_command(shell, command)
    lines = []
    for line in raw.splitlines():
        stripped = line.rstrip()
        # Drop the echoed command and IOS prompt lines
        if stripped.endswith("#") or stripped.endswith(">"):
            continue
        if stripped.lstrip().startswith(command.split()[0]):
            continue
        lines.append(stripped)
    return lines


def check_device(host: str, username: str, password: str, port: int) -> dict:
    result = {"host": host, "status": "ok", "diff": [], "error": None}
    client = None
    try:
        log.info("Connecting to %s", host)
        client = ssh_connect(host, username, password, port)
        shell = client.invoke_shell()
        time.sleep(1.0)
        shell.recv(65535)  # flush login banner and initial prompt

        send_command(shell, "terminal length 0", wait=1.0)

        running = fetch_config(shell, "show running-config")
        startup = fetch_config(shell, "show startup-config")

        diff = list(
            difflib.unified_diff(
                startup,
                running,
                fromfile=f"{host}/startup-config",
                tofile=f"{host}/running-config",
                lineterm="",
            )
        )
        result["diff"] = diff

        if diff:
            log.warning("%s: %d line(s) differ — unsaved changes present", host, len(diff))
        else:
            log.info("%s: running and startup configs match", host)

    except paramiko.AuthenticationException:
        result["status"] = "auth_failed"
        result["error"] = "Authentication failed"
        log.error("%s: authentication failed", host)
    except (paramiko.SSHException, OSError) as exc:
        result["status"] = "connection_error"
        result["error"] = str(exc)
        log.error("%s: %s", host, exc)
    finally:
        if client:
            client.close()

    return result


def format_report(results: list[dict]) -> str:
    clean = [r for r in results if r["status"] == "ok" and not r["diff"]]
    dirty = [r for r in results if r["status"] == "ok" and r["diff"]]
    failed = [r for r in results if r["status"] != "ok"]

    lines = [
        "=" * 60,
        "Running vs Startup Config Diff Report",
        "=" * 60,
        "",
        f"Devices checked   : {len(results)}",
        f"  In sync         : {len(clean)}",
        f"  Unsaved changes : {len(dirty)}",
        f"  Unreachable     : {len(failed)}",
        "",
    ]

    if dirty:
        lines.append("--- Devices with unsaved changes ---")
        for r in dirty:
            lines.append(f"\n{r['host']}:")
            lines.extend(r["diff"])

    if failed:
        lines.append("\n--- Failed connections ---")
        for r in failed:
            lines.append(f"  {r['host']}: {r['error']}")

    if clean:
        lines.append("\n--- Clean devices (running == startup) ---")
        for r in clean:
            lines.append(f"  {r['host']}")

    return "\n".join(lines)


def load_hosts(path: str) -> list[str]:
    return [
        line.strip()
        for line in Path(path).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Diff running-config vs startup-config to detect unsaved changes."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--device", help="Single device IP or hostname")
    group.add_argument("-f", "--file", help="File with device IPs, one per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-o", "--output", help="Write report to this file path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}: ")
    hosts = [args.device] if args.device else load_hosts(args.file)

    if not hosts:
        log.error("No hosts to check")
        sys.exit(1)

    results = [check_device(h, args.username, password, args.port) for h in hosts]
    report = format_report(results)
    print(report)

    if args.output:
        Path(args.output).write_text(report)
        log.info("Report written to %s", args.output)

    dirty_count = sum(1 for r in results if r["status"] == "ok" and r["diff"])
    sys.exit(1 if dirty_count else 0)
```