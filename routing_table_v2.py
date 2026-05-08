routing_change_monitor.py - Monitor a network device for routing table changes.

Connects to a device via SSH, captures an initial routing table baseline, then
polls at a configurable interval and reports any routes that are added or
removed between polls. Useful for detecting route flaps, convergence events,
or unauthorized routing changes in real time.

Usage:
    python routing_change_monitor.py -d 192.168.1.1 -u admin -p secret
    python routing_change_monitor.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa --interval 30
    python routing_change_monitor.py -d 192.168.1.1 -u admin -p secret --count 20 --output changes.log

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device. The user account needs at least
    read-only privilege to run 'show ip route' (Cisco IOS/IOS-XE) or the
    command specified via --command.
"""

import argparse
import logging
import re
import sys
import time
from datetime import datetime

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=bool(key_file),
        allow_agent=False,
    )
    if key_file:
        kwargs["key_filename"] = key_file
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key for authentication")
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def extract_routes(output):
    """Return a frozenset of network prefixes parsed from 'show ip route' output."""
    routes = set()
    # Matches route-code lines: C/S/R/O/B/E/i/D/+ etc. followed by a prefix
    pattern = re.compile(
        r"^\s*[A-Za-z*+>i]\S*\s+(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        routes.add(m.group(1))
    return frozenset(routes)


def format_report(added, removed, timestamp):
    lines = [f"\n[{timestamp}] Routing table change detected:"]
    for r in sorted(added):
        lines.append(f"  + ADDED   {r}")
    for r in sorted(removed):
        lines.append(f"  - REMOVED {r}")
    return "\n".join(lines)


def build_parser():
    p = argparse.ArgumentParser(
        description="Poll a network device and report routing table changes"
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("-k", "--key", default=None, help="Path to SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--interval", type=int, default=60,
        help="Seconds between polls (default: 60)"
    )
    p.add_argument(
        "--count", type=int, default=0,
        help="Stop after N polls; 0 runs indefinitely (default: 0)"
    )
    p.add_argument(
        "--command", default="show ip route",
        help='Command to fetch routing table (default: "show ip route")'
    )
    p.add_argument("--output", default=None, help="Append change log to this file")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = ssh_connect(
            host=args.device,
            username=args.username,
            password=args.password,
            key_file=args.key,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    log.info("Connected. Capturing baseline routing table...")
    try:
        baseline_raw = run_command(client, args.command)
    except Exception as exc:
        log.error("Failed to run '%s': %s", args.command, exc)
        client.close()
        sys.exit(1)

    previous = extract_routes(baseline_raw)
    log.info("Baseline: %d routes. Polling every %ds.", len(previous), args.interval)

    out_file = open(args.output, "a") if args.output else None
    poll = 0

    try:
        while True:
            time.sleep(args.interval)
            poll += 1

            try:
                raw = run_command(client, args.command)
            except (paramiko.SSHException, OSError) as exc:
                log.warning("Poll %d: connection lost (%s), reconnecting...", poll, exc)
                try:
                    client.close()
                    client = ssh_connect(
                        host=args.device,
                        username=args.username,
                        password=args.password,
                        key_file=args.key,
                        port=args.port,
                    )
                    raw = run_command(client, args.command)
                except Exception as reconnect_exc:
                    log.error("Reconnect failed: %s", reconnect_exc)
                    continue

            current = extract_routes(raw)
            added = current - previous
            removed = previous - current

            if added or removed:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                report = format_report(added, removed, ts)
                print(report, flush=True)
                if out_file:
                    out_file.write(report + "\n")
                    out_file.flush()
            else:
                log.debug("Poll %d: no changes (%d routes)", poll, len(current))

            previous = current

            if args.count and poll >= args.count:
                log.info("Reached poll limit (%d). Exiting.", args.count)
                break

    except KeyboardInterrupt:
        log.info("Interrupted by user")
    finally:
        client.close()
        if out_file:
            out_file.close()

    log.info("Done. Total polls: %d", poll)


if __name__ == "__main__":
    main()