```python
"""
routing_table_monitor.py - Route change detection via SSH

Connects to a Cisco IOS/IOS-XE device, captures the routing table (or a
specific prefix), compares against a saved snapshot, and reports additions
and withdrawals.  Useful for scheduled monitoring, post-change validation,
or pre/post maintenance windows.

Prerequisites:
    pip install paramiko

Usage:
    # Baseline snapshot
    python routing_table_monitor.py --host 10.0.0.1 --user admin --save

    # Detect changes since last snapshot
    python routing_table_monitor.py --host 10.0.0.1 --user admin --diff

    # Monitor a specific prefix
    python routing_table_monitor.py --host 10.0.0.1 --user admin \
        --prefix 192.168.1.0/24 --diff

    # Filter by protocol (ospf, bgp, static, connected)
    python routing_table_monitor.py --host 10.0.0.1 --user admin \
        --protocol ospf --save
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

PROTO_MAP = {
    "ospf": r"^O",
    "bgp": r"^B",
    "static": r"^S",
    "connected": r"^C",
    "eigrp": r"^D",
    "rip": r"^R",
}


def ssh_connect(host, user, password, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client, command, wait=2.0):
    chan = client.invoke_shell()
    chan.settimeout(10)
    time.sleep(0.5)
    chan.recv(4096)  # drain banner
    chan.send("terminal length 0\n")
    time.sleep(0.3)
    chan.recv(4096)
    chan.send(command + "\n")
    time.sleep(wait)
    output = ""
    while chan.recv_ready():
        output += chan.recv(8192).decode("utf-8", errors="replace")
        time.sleep(0.1)
    chan.close()
    return output


def parse_routes(raw, protocol_filter=None, prefix_filter=None):
    routes = {}
    current_prefix = None
    proto_re = re.compile(
        r"^([A-Z*]{1,2}(?:\s+[A-Z]+)?)\s+"
        r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})"
        r".*?via\s+(\d{1,3}(?:\.\d{1,3}){3})",
        re.MULTILINE,
    )
    for m in proto_re.finditer(raw):
        code, prefix, via = m.group(1).strip(), m.group(2), m.group(3)
        if protocol_filter:
            pattern = PROTO_MAP.get(protocol_filter.lower())
            if pattern and not re.match(pattern, code, re.IGNORECASE):
                continue
        if prefix_filter and prefix != prefix_filter:
            continue
        routes.setdefault(prefix, []).append({"code": code, "via": via})
    return routes


def snapshot_path(host, prefix_filter, protocol_filter):
    tag = host.replace(".", "_")
    if prefix_filter:
        tag += "_" + prefix_filter.replace("/", "-")
    if protocol_filter:
        tag += "_" + protocol_filter
    return Path(f".route_snapshot_{tag}.json")


def save_snapshot(routes, path):
    data = {"timestamp": datetime.utcnow().isoformat(), "routes": routes}
    path.write_text(json.dumps(data, indent=2))
    log.info("Snapshot saved to %s (%d prefixes)", path, len(routes))


def diff_routes(old_routes, new_routes):
    added = {k: new_routes[k] for k in new_routes if k not in old_routes}
    removed = {k: old_routes[k] for k in old_routes if k not in new_routes}
    changed = {}
    for k in new_routes:
        if k in old_routes and old_routes[k] != new_routes[k]:
            changed[k] = {"before": old_routes[k], "after": new_routes[k]}
    return added, removed, changed


def main():
    parser = argparse.ArgumentParser(
        description="Monitor routing table changes on a Cisco IOS device"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--prefix", help="Filter to a specific prefix (e.g. 10.0.0.0/8)")
    parser.add_argument(
        "--protocol",
        choices=list(PROTO_MAP.keys()),
        help="Filter by routing protocol",
    )
    parser.add_argument(
        "--save", action="store_true", help="Save current table as baseline snapshot"
    )
    parser.add_argument(
        "--diff", action="store_true", help="Compare current table against snapshot"
    )
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    if not args.save and not args.diff:
        parser.error("Specify --save to capture a baseline or --diff to compare")

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")
    snap = snapshot_path(args.host, args.prefix, args.protocol)

    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        client = ssh_connect(args.host, args.user, password, args.port, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        cmd = "show ip route" + (f" {args.prefix}" if args.prefix else "")
        log.info("Running: %s", cmd)
        raw = run_command(client, cmd)
    finally:
        client.close()

    routes = parse_routes(raw, args.protocol, args.prefix)
    log.info("Parsed %d prefixes", len(routes))

    if args.save:
        save_snapshot(routes, snap)

    if args.diff:
        if not snap.exists():
            log.error("No snapshot found at %s — run with --save first", snap)
            sys.exit(1)
        stored = json.loads(snap.read_text())
        log.info("Comparing against snapshot from %s", stored["timestamp"])
        added, removed, changed = diff_routes(stored["routes"], routes)
        if not added and not removed and not changed:
            print("No route changes detected.")
        else:
            if added:
                print(f"\n[+] Added ({len(added)} prefix(es)):")
                for p, hops in added.items():
                    print(f"    {p}  via {', '.join(h['via'] for h in hops)}")
            if removed:
                print(f"\n[-] Removed ({len(removed)} prefix(es)):")
                for p, hops in removed.items():
                    print(f"    {p}  via {', '.join(h['via'] for h in hops)}")
            if changed:
                print(f"\n[~] Changed next-hop ({len(changed)} prefix(es)):")
                for p, delta in changed.items():
                    before = ", ".join(h["via"] for h in delta["before"])
                    after = ", ".join(h["via"] for h in delta["after"])
                    print(f"    {p}  {before} -> {after}")
        if args.save:
            save_snapshot(routes, snap)


if __name__ == "__main__":
    main()
```