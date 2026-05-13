```python
"""
route_change_monitor.py - Detect routing table changes against a saved baseline.

Purpose:
    Connects to a network device via SSH, captures the current routing table,
    and compares it against a previously saved baseline snapshot. Useful for
    post-change validation, detecting unexpected route withdrawals or additions,
    and confirming convergence after maintenance windows.

Usage:
    # Save a baseline:
    python route_change_monitor.py -H 192.168.1.1 -u admin -p secret --save-baseline

    # Compare against saved baseline:
    python route_change_monitor.py -H 192.168.1.1 -u admin -p secret

    # Use a custom baseline file:
    python route_change_monitor.py -H 192.168.1.1 -u admin -p secret --baseline routes_before.json

Prerequisites:
    pip install paramiko
"""

import argparse
import json
import logging
import re
import sys
import time
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_run(host, port, username, password, command, timeout=30):
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
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.warning("stderr: %s", err)
        return output
    finally:
        client.close()


def parse_routes(raw_output):
    """Extract prefix/next-hop pairs from Cisco IOS 'show ip route' output."""
    routes = {}
    # Matches lines like: C 10.0.0.0/8 is directly connected, GigabitEthernet0/0
    # or: S    192.168.1.0/24 [1/0] via 10.0.0.1
    prefix_re = re.compile(
        r"^\s*[A-Z*>i]\S*\s+"
        r"((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)"
        r"(?:\s+\[[\d/]+\])?"
        r"(?:\s+via\s+(\S+))?",
        re.MULTILINE,
    )
    for match in prefix_re.finditer(raw_output):
        prefix = match.group(1)
        nexthop = match.group(2) or "directly-connected"
        routes[prefix] = nexthop
    return routes


def diff_routes(baseline, current):
    added = {p: current[p] for p in current if p not in baseline}
    removed = {p: baseline[p] for p in baseline if p not in current}
    changed = {
        p: {"before": baseline[p], "after": current[p]}
        for p in current
        if p in baseline and current[p] != baseline[p]
    }
    return added, removed, changed


def main():
    parser = argparse.ArgumentParser(
        description="Monitor routing table changes against a saved baseline."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--command",
        default="show ip route",
        help="Routing table command (default: 'show ip route')",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Baseline JSON file path (default: <host>_routes_baseline.json)",
    )
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Capture current routes as the new baseline and exit",
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="SSH timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 if any changes are detected",
    )
    args = parser.parse_args()

    baseline_path = Path(args.baseline or f"{args.host}_routes_baseline.json")

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        raw = ssh_run(
            args.host,
            args.port,
            args.username,
            args.password,
            args.command,
            args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(2)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(2)

    current_routes = parse_routes(raw)
    log.info("Parsed %d routes from device", len(current_routes))

    if args.save_baseline:
        payload = {
            "host": args.host,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "routes": current_routes,
        }
        baseline_path.write_text(json.dumps(payload, indent=2))
        log.info("Baseline saved to %s (%d routes)", baseline_path, len(current_routes))
        sys.exit(0)

    if not baseline_path.exists():
        log.error(
            "No baseline found at %s. Run with --save-baseline first.", baseline_path
        )
        sys.exit(2)

    baseline_data = json.loads(baseline_path.read_text())
    baseline_routes = baseline_data.get("routes", {})
    baseline_ts = baseline_data.get("timestamp", "unknown")
    log.info("Loaded baseline from %s (captured %s)", baseline_path, baseline_ts)

    added, removed, changed = diff_routes(baseline_routes, current_routes)

    if not added and not removed and not changed:
        print("No routing table changes detected.")
        sys.exit(0)

    if added:
        print(f"\nADDED ({len(added)}):")
        for prefix, nexthop in sorted(added.items()):
            print(f"  + {prefix}  via {nexthop}")

    if removed:
        print(f"\nREMOVED ({len(removed)}):")
        for prefix, nexthop in sorted(removed.items()):
            print(f"  - {prefix}  via {nexthop}")

    if changed:
        print(f"\nNEXT-HOP CHANGED ({len(changed)}):")
        for prefix, hops in sorted(changed.items()):
            print(f"  ~ {prefix}  {hops['before']} -> {hops['after']}")

    total = len(added) + len(removed) + len(changed)
    print(f"\nSummary: {total} change(s) detected vs baseline from {baseline_ts}")

    if args.exit_code:
        sys.exit(1)


if __name__ == "__main__":
    main()
```