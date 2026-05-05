running_startup_diff.py — Detect unsaved configuration changes on a network device.

Purpose:
    Fetches 'show running-config' and 'show startup-config' over SSH and produces
    a unified diff.  Any lines present in running but absent from startup represent
    changes that will be lost on reload; lines present only in startup have been
    removed from the live config without saving.  Useful for change-window audits,
    compliance checks, and pre-reload verification.

Usage:
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret
    python running_startup_diff.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python running_startup_diff.py -H 192.168.1.1 -u admin -p secret --context 5 --out diff.txt

Prerequisites:
    pip install paramiko
    SSH access with privilege level 15 (Cisco) or equivalent read-only exec access.
    Device must support 'terminal length 0' to suppress pagination.
"""

import argparse
import difflib
import logging
import sys
import time
from datetime import datetime, timezone

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def _connect(host: str, port: int, username: str,
             password: str | None, key_path: str | None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 15,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _open_shell(client: paramiko.SSHClient) -> paramiko.Channel:
    shell = client.invoke_shell(width=200, height=50000)
    time.sleep(1.0)
    while shell.recv_ready():
        shell.recv(65535)
    shell.send("terminal length 0\n")
    time.sleep(0.5)
    while shell.recv_ready():
        shell.recv(65535)
    return shell


def _fetch(shell: paramiko.Channel, command: str, timeout: int = 45) -> list[str]:
    shell.send(command + "\n")
    output = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if output.rstrip().endswith("#"):
                break
        else:
            time.sleep(0.1)
    else:
        log.warning("Timeout waiting for response to: %s", command)

    lines = output.splitlines()
    # Strip echoed command line
    if lines and command.strip() in lines[0]:
        lines = lines[1:]
    # Strip trailing prompt
    if lines and lines[-1].rstrip().endswith("#"):
        lines = lines[:-1]
    return [ln.rstrip() for ln in lines]


def diff_running_vs_startup(
    host: str,
    port: int,
    username: str,
    password: str | None,
    key_path: str | None,
    context: int,
) -> tuple[list[str], list[str], list[str]]:
    """Return (running_lines, startup_lines, unified_diff_lines)."""
    log.info("Connecting to %s:%d", host, port)
    client = _connect(host, port, username, password, key_path)
    try:
        shell = _open_shell(client)
        log.info("Fetching running-config")
        running = _fetch(shell, "show running-config")
        log.info("Fetching startup-config")
        startup = _fetch(shell, "show startup-config")
    finally:
        client.close()

    diff = list(
        difflib.unified_diff(
            startup,
            running,
            fromfile="startup-config",
            tofile="running-config",
            lineterm="",
            n=context,
        )
    )
    return running, startup, diff


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Diff running-config vs startup-config to surface unsaved changes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", default=None, metavar="PATH", help="SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--context", type=int, default=3, help="Diff context lines")
    parser.add_argument("--out", default=None, metavar="FILE", help="Write diff to file")
    parser.add_argument("--quiet", action="store_true", help="Suppress INFO messages")
    args = parser.parse_args()

    if args.quiet:
        log.setLevel(logging.WARNING)
    if not args.password and not args.key:
        parser.error("Provide --password or --key for authentication.")

    try:
        _, _, diff = diff_running_vs_startup(
            args.host, args.port, args.username, args.password, args.key, args.context
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        return 1
    except OSError as exc:
        log.error("Connection failed: %s", exc)
        return 1

    if not diff:
        log.info("Clean — running-config matches startup-config on %s.", args.host)
        return 0

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = [
        f"# host={args.host}  time={timestamp}  ({len(diff)} diff lines)",
        "# + lines exist in running but not startup (unsaved additions)",
        "# - lines exist in startup but not running (unsaved deletions)",
        "",
    ]
    output = "\n".join(header + diff) + "\n"

    if args.out:
        try:
            with open(args.out, "w") as fh:
                fh.write(output)
            log.info("Diff written to %s", args.out)
        except OSError as exc:
            log.error("Could not write %s: %s", args.out, exc)
            return 1
    else:
        sys.stdout.write(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())