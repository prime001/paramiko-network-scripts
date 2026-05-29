Routing Table Change Monitor

Polls a network device's routing table at a configurable interval and reports
when routes are added or removed. Useful for detecting unplanned topology
changes, flapping routes, or validating convergence after maintenance.

Usage:
    python routing_table_monitor.py -d 192.168.1.1 -u admin -p secret
    python routing_table_monitor.py -d 192.168.1.1 -u admin --ask-pass \
        --interval 30 --count 10 --output changes.log

Prerequisites:
    pip install paramiko
    SSH access to the target device (Cisco IOS/IOS-XE/NX-OS)
"""

import argparse
import getpass
import hashlib
import logging
import re
import sys
import time
from datetime import datetime

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    if error.strip():
        logger.debug("stderr: %s", error.strip())
    return output


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return client


def fetch_routes(client: paramiko.SSHClient) -> set[str]:
    """Return a set of route prefix strings from 'show ip route'."""
    raw = ssh_exec(client, "show ip route")
    routes = set()
    pattern = re.compile(
        r"^[A-Z*>i\s]{1,3}\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)",
        re.MULTILINE,
    )
    for match in pattern.finditer(raw):
        routes.add(match.group(1))
    return routes


def route_fingerprint(routes: set[str]) -> str:
    return hashlib.md5("|".join(sorted(routes)).encode()).hexdigest()


def format_diff(added: set[str], removed: set[str]) -> str:
    lines = []
    for r in sorted(removed):
        lines.append(f"  - REMOVED  {r}")
    for r in sorted(added):
        lines.append(f"  + ADDED    {r}")
    return "\n".join(lines)


def monitor(args: argparse.Namespace) -> None:
    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    log_file = None
    if args.output:
        log_file = open(args.output, "a")

    try:
        logger.info("Connecting to %s:%d", args.device, args.port)
        client = connect(args.device, args.port, args.username, password)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        logger.info("Taking initial routing table snapshot...")
        previous = fetch_routes(client)
        prev_fp = route_fingerprint(previous)
        logger.info("Baseline: %d routes (fingerprint %s)", len(previous), prev_fp[:8])

        poll_count = 0
        change_count = 0

        while True:
            time.sleep(args.interval)
            poll_count += 1

            try:
                current = fetch_routes(client)
            except Exception as exc:
                logger.warning("Poll %d failed: %s — reconnecting", poll_count, exc)
                try:
                    client.close()
                    client = connect(args.device, args.port, args.username, password)
                    current = fetch_routes(client)
                except Exception as reconnect_exc:
                    logger.error("Reconnect failed: %s", reconnect_exc)
                    break

            curr_fp = route_fingerprint(current)
            if curr_fp == prev_fp:
                logger.info("Poll %d — no change (%d routes)", poll_count, len(current))
            else:
                added = current - previous
                removed = previous - current
                change_count += 1
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                msg = (
                    f"\n[{ts}] CHANGE #{change_count} detected on {args.device} "
                    f"(poll {poll_count})\n"
                    f"  Routes before: {len(previous)}  after: {len(current)}\n"
                    + format_diff(added, removed)
                )
                logger.warning(msg)
                if log_file:
                    log_file.write(msg + "\n")
                    log_file.flush()

                previous = current
                prev_fp = curr_fp

            if args.count and poll_count >= args.count:
                logger.info("Reached poll limit (%d). Exiting.", args.count)
                break

    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    finally:
        client.close()
        if log_file:
            log_file.close()
        logger.info(
            "Session ended. Total polls: %d, changes detected: %d",
            poll_count,
            change_count,
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor routing table changes on a network device via SSH."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompts if omitted)")
    p.add_argument("--ask-pass", action="store_true", help="Force interactive password prompt")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--interval", type=int, default=60,
        help="Polling interval in seconds (default: 60)",
    )
    p.add_argument(
        "--count", type=int, default=0,
        help="Stop after N polls (default: 0 = run forever)",
    )
    p.add_argument("--output", metavar="FILE", help="Append change events to FILE")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.ask_pass:
        args.password = None

    monitor(args)