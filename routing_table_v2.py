```python
"""
Route Change Monitor — SSH-based IP routing table change detection.

Purpose:
    Connects to a network device via SSH and detects changes in the IP routing
    table by comparing the current state against a saved baseline snapshot.
    Useful for auditing unexpected route additions, withdrawals, or next-hop
    shifts after maintenance windows or BGP/OSPF events.

Usage:
    # Save a baseline snapshot
    python route_change_monitor.py -d 192.168.1.1 -u admin --save-baseline

    # Compare current table against the saved baseline
    python route_change_monitor.py -d 192.168.1.1 -u admin --check

    # Continuous monitoring — poll every N seconds, report changes between polls
    python route_change_monitor.py -d 192.168.1.1 -u admin --watch --interval 60

Prerequisites:
    pip install paramiko
    SSH access with sufficient privileges to run 'show ip route' (Cisco IOS/NX-OS)
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
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client, command, recv_timeout=10):
    _, stdout, stderr = client.exec_command(command, timeout=recv_timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.warning("Device stderr: %s", err)
    return output


def parse_routes(raw_output):
    """Return {prefix: nexthop} from 'show ip route' output."""
    routes = {}
    via_pattern = re.compile(
        r"^[COSRBEIDO\s*>]+\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+\[[\d/]+\]\s+via\s+(\S+)",
        re.MULTILINE,
    )
    connected_pattern = re.compile(
        r"^[C\s]+(\d+\.\d+\.\d+\.\d+/\d+)\s+is directly connected,\s+(\S+)",
        re.MULTILINE,
    )
    for m in via_pattern.finditer(raw_output):
        routes[m.group(1)] = m.group(2).rstrip(",")
    for m in connected_pattern.finditer(raw_output):
        routes[m.group(1)] = f"direct:{m.group(2)}"
    return routes


def snapshot_path(host, baseline_dir):
    safe = re.sub(r"[^\w]", "_", host)
    return Path(baseline_dir) / f"{safe}_routes.json"


def save_snapshot(host, routes, baseline_dir):
    path = snapshot_path(host, baseline_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "host": host,
        "timestamp": datetime.utcnow().isoformat(),
        "routes": routes,
    }, indent=2))
    log.info("Baseline saved → %s  (%d routes)", path, len(routes))


def load_snapshot(host, baseline_dir):
    path = snapshot_path(host, baseline_dir)
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    log.info("Baseline loaded from %s  (saved %s, %d routes)",
             path, data.get("timestamp", "?"), len(data["routes"]))
    return data["routes"]


def diff_routes(baseline, current):
    added = {p: current[p] for p in current if p not in baseline}
    removed = {p: baseline[p] for p in baseline if p not in current}
    changed = {
        p: {"was": baseline[p], "now": current[p]}
        for p in current
        if p in baseline and current[p] != baseline[p]
    }
    return added, removed, changed


def print_diff(added, removed, changed):
    if not (added or removed or changed):
        print("  No routing table changes detected.")
        return False
    if added:
        print(f"  ADDED ({len(added)}):")
        for prefix, nh in sorted(added.items()):
            print(f"    + {prefix:<24} via {nh}")
    if removed:
        print(f"  REMOVED ({len(removed)}):")
        for prefix, nh in sorted(removed.items()):
            print(f"    - {prefix:<24} via {nh}")
    if changed:
        print(f"  NEXT-HOP CHANGED ({len(changed)}):")
        for prefix, info in sorted(changed.items()):
            print(f"    ~ {prefix:<24} {info['was']}  →  {info['now']}")
    return True


def collect(args, password):
    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(args.device, args.username, password, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)
    try:
        raw = run_command(client, "show ip route")
        routes = parse_routes(raw)
        log.info("Collected %d routes from %s", len(routes), args.device)
        return routes
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Monitor IP routing table changes on network devices via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None,
                        help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--baseline-dir", default="./route_baselines",
                        help="Directory for baseline snapshots (default: ./route_baselines)")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--save-baseline", action="store_true",
                      help="Collect current routes and save as the new baseline")
    mode.add_argument("--check", action="store_true",
                      help="Compare current routes against the saved baseline")
    mode.add_argument("--watch", action="store_true",
                      help="Poll continuously; report changes between each poll")

    parser.add_argument("--interval", type=int, default=60,
                        help="Poll interval in seconds for --watch mode (default: 60)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    if args.save_baseline:
        routes = collect(args, password)
        save_snapshot(args.device, routes, args.baseline_dir)

    elif args.check:
        baseline = load_snapshot(args.device, args.baseline_dir)
        if baseline is None:
            log.error("No baseline found. Run --save-baseline first.")
            sys.exit(1)
        current = collect(args, password)
        added, removed, changed = diff_routes(baseline, current)
        print(f"\n{args.device} — route diff vs baseline:")
        has_changes = print_diff(added, removed, changed)
        sys.exit(1 if has_changes else 0)

    elif args.watch:
        log.info("Watch mode active (interval: %ds). Ctrl-C to stop.", args.interval)
        previous = collect(args, password)
        print(f"[{datetime.now():%H:%M:%S}] Monitoring {args.device} — "
              f"baseline: {len(previous)} routes")
        try:
            while True:
                time.sleep(args.interval)
                current = collect(args, password)
                added, removed, changed = diff_routes(previous, current)
                ts = datetime.now().strftime("%H:%M:%S")
                if added or removed or changed:
                    print(f"\n[{ts}] CHANGES on {args.device}:")
                    print_diff(added, removed, changed)
                else:
                    print(f"[{ts}] No changes  ({len(current)} routes)")
                previous = current
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")


if __name__ == "__main__":
    main()
```