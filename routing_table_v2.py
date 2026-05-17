The task asks to output the script content only — not write it to a file. Here is the script:

```python
"""
routing_table_monitor.py — Routing Table Change Monitor

Polls a network device at a configurable interval and reports when routes
are added or removed. Useful for detecting routing instability, convergence
events, or unauthorized route injection during maintenance windows.

Usage:
    python routing_table_monitor.py -H 192.168.1.1 -u admin -p secret
    python routing_table_monitor.py -H 10.0.0.1 -u admin -k ~/.ssh/id_rsa --interval 30
    python routing_table_monitor.py -H 10.0.0.1 -u admin -p secret --once --output routes.json

Prerequisites:
    pip install paramiko
    Device must support 'show ip route' (Cisco IOS/IOS-XE) or equivalent.
"""

import argparse
import getpass
import json
import logging
import re
import signal
import sys
import time
from datetime import datetime
from typing import Optional

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

_running = True


def _sigint(sig, frame):
    global _running
    log.info("Caught SIGINT, stopping monitor.")
    _running = False


signal.signal(signal.SIGINT, _sigint)


def connect(host: str, port: int, username: str, password: Optional[str],
            key_path: Optional[str], timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username,
                  timeout=timeout, allow_agent=False, look_for_keys=False)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def fetch_routes(client: paramiko.SSHClient, command: str) -> set:
    _, stdout, stderr = client.exec_command(command, timeout=30)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return parse_routes(output)


def parse_routes(output: str) -> set:
    """Extract (prefix, nexthop) pairs from 'show ip route' output."""
    routes = set()
    # Matches: S    10.0.0.0/8 [1/0] via 192.168.1.254
    prefix_re = re.compile(
        r"^\s*[A-Z*>i]\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)"
        r"(?:\s+\[\d+/\d+\])?\s+via\s+(\d+\.\d+\.\d+\.\d+)",
        re.MULTILINE,
    )
    for m in prefix_re.finditer(output):
        routes.add((m.group(1), m.group(2)))
    connected_re = re.compile(
        r"^\s*[CL]\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+is directly connected",
        re.MULTILINE,
    )
    for m in connected_re.finditer(output):
        routes.add((m.group(1), "directly-connected"))
    return routes


def diff_routes(before: set, after: set) -> tuple:
    return after - before, before - after


def report_changes(added: set, removed: set, host: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for prefix, nexthop in sorted(added):
        log.warning("[%s] ADDED   %s via %s", host, prefix, nexthop)
    for prefix, nexthop in sorted(removed):
        log.warning("[%s] REMOVED %s via %s", host, prefix, nexthop)
    if not added and not removed:
        log.info("[%s] No routing changes at %s", host, ts)


def snapshot_to_dict(routes: set) -> list:
    return sorted([{"prefix": p, "nexthop": n} for p, n in routes],
                  key=lambda x: x["prefix"])


def main():
    parser = argparse.ArgumentParser(
        description="Monitor routing table changes on a network device."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None,
                        help="Password (prompted if omitted and no key given)")
    parser.add_argument("-k", "--key", dest="key_path", default=None,
                        help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=15,
                        help="SSH connect timeout in seconds (default: 15)")
    parser.add_argument("--interval", type=int, default=60,
                        help="Poll interval in seconds (default: 60)")
    parser.add_argument("--command", default="show ip route",
                        help="Command to run (default: 'show ip route')")
    parser.add_argument("--once", action="store_true",
                        help="Fetch once, print routes as JSON, and exit")
    parser.add_argument("--output", default=None,
                        help="Write final route snapshot to this JSON file")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if not args.key_path and args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        client = connect(args.host, args.port, args.username,
                         args.password, args.key_path, args.timeout)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    log.info("Connected to %s. Fetching initial routing table...", args.host)
    try:
        current = fetch_routes(client, args.command)
    except Exception as exc:
        log.error("Failed to fetch routes: %s", exc)
        client.close()
        sys.exit(1)

    log.info("Baseline: %d route entries", len(current))

    if args.once:
        snapshot = snapshot_to_dict(current)
        print(json.dumps(snapshot, indent=2))
        if args.output:
            with open(args.output, "w") as f:
                json.dump(snapshot, f, indent=2)
            log.info("Snapshot written to %s", args.output)
        client.close()
        return

    log.info("Monitoring every %ds. Press Ctrl+C to stop.", args.interval)
    while _running:
        time.sleep(args.interval)
        if not _running:
            break
        try:
            previous = current
            current = fetch_routes(client, args.command)
            added, removed = diff_routes(previous, current)
            report_changes(added, removed, args.host)
        except Exception as exc:
            log.error("Poll failed: %s — attempting reconnect", exc)
            try:
                client.close()
                client = connect(args.host, args.port, args.username,
                                 args.password, args.key_path, args.timeout)
                log.info("Reconnected to %s", args.host)
            except Exception as reconn_exc:
                log.error("Reconnect failed: %s", reconn_exc)

    if args.output:
        snapshot = snapshot_to_dict(current)
        with open(args.output, "w") as f:
            json.dump(snapshot, f, indent=2)
        log.info("Final snapshot written to %s", args.output)

    client.close()
    log.info("Monitor stopped.")


if __name__ == "__main__":
    main()
```