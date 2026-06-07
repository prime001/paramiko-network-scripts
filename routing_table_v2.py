The `paramiko-network-scripts` repo isn't on the local filesystem — the user wants the script content printed directly. Here it is:

```
"""
routing_table_monitor.py - Routing Table Change Monitor

Captures the routing table from a Cisco IOS/IOS-XE/NX-OS device via SSH and
compares it against a saved baseline to detect added, removed, or rerouted
prefixes.  Designed for change-management workflows: save a pre-change baseline,
make your change, then diff to confirm only the expected routes moved.

Usage:
    # Save a pre-change baseline
    python routing_table_monitor.py -H 10.0.0.1 -u admin -p secret --save pre.json

    # Compare post-change state against the baseline
    python routing_table_monitor.py -H 10.0.0.1 -u admin -p secret --compare pre.json

    # Dump current routes as JSON (useful for inventory pipelines)
    python routing_table_monitor.py -H 10.0.0.1 -u admin -p secret --output routes.json

    # Target a specific VRF
    python routing_table_monitor.py -H 10.0.0.1 -u admin -p secret --vrf MGMT --compare pre.json

Prerequisites:
    pip install paramiko
    SSH enabled on the device; credentials with at least 'show' privilege
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

_PREFIX_RE = re.compile(
    r"^\s*[A-Z*i>][A-Z*i\s]{0,3}"
    r"\s+(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)"
)
_NEXTHOP_RE = re.compile(r"via\s+(\d{1,3}(?:\.\d{1,3}){3})")
_AD_METRIC_RE = re.compile(r"\[(\d+)/(\d+)\]")
_PROTO_RE = re.compile(r"^\s*([A-Z*i][A-Z*i\s]{0,2})")


def _connect(host, username, password, port, timeout):
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


def _run(client, cmd, timeout=30):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return out


def parse_routes(raw):
    """Return dict keyed by prefix with nexthop/protocol metadata."""
    routes = {}
    for line in raw.splitlines():
        pm = _PREFIX_RE.match(line)
        if not pm:
            continue
        prefix = pm.group(1)
        if "/" not in prefix:
            prefix += "/32"
        proto_m = _PROTO_RE.match(line)
        proto = proto_m.group(1).strip().lstrip("*> ") if proto_m else "?"
        nh_m = _NEXTHOP_RE.search(line)
        ad_m = _AD_METRIC_RE.search(line)
        routes[prefix] = {
            "protocol": proto,
            "nexthop": nh_m.group(1) if nh_m else None,
            "admin_distance": int(ad_m.group(1)) if ad_m else None,
            "metric": int(ad_m.group(2)) if ad_m else None,
        }
    return routes


def diff_routes(baseline, current):
    b, c = set(baseline), set(current)
    added = {p: current[p] for p in c - b}
    removed = {p: baseline[p] for p in b - c}
    changed = {
        p: {"before": baseline[p], "after": current[p]}
        for p in b & c
        if baseline[p]["nexthop"] != current[p]["nexthop"]
    }
    return added, removed, changed


def print_diff(added, removed, changed):
    if not any([added, removed, changed]):
        print("No routing table changes detected.")
        return
    if added:
        print(f"\n[+] {len(added)} prefix(es) ADDED:")
        for pfx, r in sorted(added.items()):
            print(f"    {pfx:<22}  via {r['nexthop'] or 'N/A'}  ({r['protocol']})")
    if removed:
        print(f"\n[-] {len(removed)} prefix(es) REMOVED:")
        for pfx, r in sorted(removed.items()):
            print(f"    {pfx:<22}  was via {r['nexthop'] or 'N/A'}  ({r['protocol']})")
    if changed:
        print(f"\n[~] {len(changed)} prefix(es) with CHANGED nexthop:")
        for pfx, d in sorted(changed.items()):
            print(f"    {pfx:<22}  {d['before']['nexthop']} -> {d['after']['nexthop']}")


def build_parser():
    p = argparse.ArgumentParser(
        description="Detect routing table changes on a network device"
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    p.add_argument("--vrf", help="VRF name (omit for global table)")
    p.add_argument(
        "--save", metavar="FILE", nargs="?", const="baseline.json",
        help="Save snapshot as baseline JSON (default filename: baseline.json)",
    )
    p.add_argument(
        "--compare", metavar="FILE",
        help="Compare current routing table against a baseline JSON file",
    )
    p.add_argument("--output", metavar="FILE", help="Write current routes to JSON")
    p.add_argument("--debug", action="store_true")
    return p


def main():
    args = build_parser().parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    cmd = f"show ip route vrf {args.vrf}" if args.vrf else "show ip route"

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = _connect(args.host, args.username, args.password, args.port, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed")
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        log.info("Running: %s", cmd)
        raw = _run(client, cmd, timeout=args.timeout)
    finally:
        client.close()

    routes = parse_routes(raw)
    log.info("Parsed %d routes", len(routes))

    snapshot = {
        "host": args.host,
        "vrf": args.vrf or "global",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "route_count": len(routes),
        "routes": routes,
    }

    if args.output:
        Path(args.output).write_text(json.dumps(snapshot, indent=2))
        log.info("Routes written to %s", args.output)

    if args.save:
        Path(args.save).write_text(json.dumps(snapshot, indent=2))
        log.info("Baseline saved: %s (%d routes)", args.save, len(routes))

    if args.compare:
        bl_path = Path(args.compare)
        if not bl_path.exists():
            log.error("Baseline file not found: %s", args.compare)
            sys.exit(1)
        bl = json.loads(bl_path.read_text())
        log.info(
            "Baseline: %s  %d routes", bl.get("timestamp", "?"), len(bl.get("routes", {}))
        )
        added, removed, changed = diff_routes(bl.get("routes", {}), routes)
        print_diff(added, removed, changed)
        if added or removed or changed:
            sys.exit(2)
        return

    if not args.save and not args.output:
        print(json.dumps(snapshot, indent=2))


if __name__ == "__main__":
    main()
```