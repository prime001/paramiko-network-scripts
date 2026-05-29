running_startup_diff.py — Detect unsaved configuration changes on network devices.

Connects via SSH (paramiko), fetches both 'show running-config' and
'show startup-config', then produces a unified diff. Useful for change
auditing, pre-maintenance checks, and cron-based drift detection.

Exit codes:
    0 — configs match (no unsaved changes)
    1 — connection or authentication error
    2 — diff exists (unsaved changes found)

Prerequisites:
    pip install paramiko

Usage:
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret
    python running_startup_diff.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret \
        --context 5 --output /tmp/drift.txt --save-on-diff
"""

import argparse
import difflib
import getpass
import logging
import sys
import time
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def ssh_connect(
    host: str,
    username: str,
    password: Optional[str] = None,
    key_file: Optional[str] = None,
    port: int = 22,
    timeout: int = 30,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    elif password:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def send_command(shell: paramiko.Channel, command: str, wait: float = 2.5) -> str:
    shell.send(command + "\n")
    time.sleep(wait)
    output = []
    while shell.recv_ready():
        output.append(shell.recv(65535).decode("utf-8", errors="replace"))
    return "".join(output)


def fetch_config(shell: paramiko.Channel, command: str) -> List[str]:
    raw = send_command(shell, command, wait=3.5)
    lines = []
    for line in raw.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("#") or stripped.endswith(">"):
            continue
        if stripped.strip() == command.strip():
            continue
        lines.append(stripped)
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def build_diff(
    running: List[str], startup: List[str], context: int = 3
) -> List[str]:
    return list(
        difflib.unified_diff(
            startup,
            running,
            fromfile="startup-config",
            tofile="running-config",
            lineterm="",
            n=context,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Diff running-config vs startup-config to detect unsaved changes"
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", metavar="FILE", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Connection timeout in seconds"
    )
    parser.add_argument(
        "--context",
        type=int,
        default=3,
        help="Lines of context around each diff hunk (default: 3)",
    )
    parser.add_argument(
        "--output", metavar="FILE", help="Write diff to file instead of stdout"
    )
    parser.add_argument(
        "--save-on-diff",
        action="store_true",
        help="Issue 'write memory' when unsaved changes are found",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress informational messages; rely on exit code",
    )
    args = parser.parse_args()

    if not args.key and not args.password:
        args.password = getpass.getpass(
            f"Password for {args.username}@{args.host}: "
        )

    if args.quiet:
        logger.setLevel(logging.WARNING)

    try:
        logger.info("Connecting to %s:%d", args.host, args.port)
        client = ssh_connect(
            args.host,
            args.username,
            password=args.password,
            key_file=args.key,
            port=args.port,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        return 1

    try:
        shell = client.invoke_shell(width=220, height=200)
        time.sleep(1.5)
        shell.recv(65535)

        send_command(shell, "terminal length 0", wait=1.0)

        logger.info("Fetching running-config from %s", args.host)
        running = fetch_config(shell, "show running-config")

        logger.info("Fetching startup-config from %s", args.host)
        startup = fetch_config(shell, "show startup-config")

        diff = build_diff(running, startup, context=args.context)

        if not diff:
            logger.info(
                "Clean: running-config matches startup-config on %s", args.host
            )
            return 0

        logger.info(
            "Drift detected on %s: %d diff lines", args.host, len(diff)
        )
        diff_text = "\n".join(diff)

        if args.output:
            with open(args.output, "w") as fh:
                fh.write(diff_text + "\n")
            logger.info("Diff written to %s", args.output)
        else:
            print(diff_text)

        if args.save_on_diff:
            logger.info("Saving configuration on %s (write memory)", args.host)
            send_command(shell, "write memory", wait=4.0)
            logger.info("Configuration saved on %s", args.host)

        return 2

    except paramiko.SSHException as exc:
        logger.error("SSH error during command execution: %s", exc)
        return 1
    finally:
        client.close()
        logger.debug("SSH connection to %s closed", args.host)


if __name__ == "__main__":
    sys.exit(main())