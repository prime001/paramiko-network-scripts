```python
"""
routing_table_monitor.py - Routing table change detection via SSH

Connects to a Cisco IOS (or compatible) device, captures the IP routing table,
and diffs it against a saved baseline snapshot. Practical for detecting route
injection, confirming maintenance changes landed correctly, or alerting on
unexpected routing instability.

Usage:
    # First run — saves baseline automatically:
    python routing_table_monitor.py -H 192.168.1.1 -u admin -p secret

    # Subsequent runs — compare against baseline:
    python routing_table_monitor.py -H 192.168.1.1 -u admin -p secret

    # Save a fresh baseline after a planned change:
    python routing_table_monitor.py -H 192.168.1.1 -u admin -k ~/.ssh/id_rsa --save

    # Custom baseline file and routing command:
    python routing_table_monitor.py -H 10.0.0.1 -u admin -p secret \
        --baseline /tmp/core1.json --command "show ip route vrf MGMT"

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
logger = logging.getLogger(__name__)

# Matches prefixes on route lines: letter code(s), optional * or >, then x.x.x.x/n
_ROUTE_RE = re.compile(
    r"^\s*[A-Za-z][A-Za-z*\s]{0,4}"
    r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})",
    re.MULTILINE,
)
# Directly connected lines lack "via"; match them separately
_CONNECTED_RE = re.compile(
    r"^\s*[CL]\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+is\s+directly",
    re.MULTILINE,
)


def _connect(host, username, password, key_file, port, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_file),
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key-file")
    client.connect(**kwargs)
    return client


def _run(client, command, recv_timeout):
    shell = client.invoke_shell()
    time.sleep(0.8)
    shell.recv(8192)
    shell.send("terminal length 0\n")
    time.sleep(0.4)
    shell.recv(8192)
    shell.send(command + "\n")

    output = ""
    deadline = time.time() + recv_timeout
    while time.time() < deadline:
        if shell.recv_ready():
            output += shell.recv(65535).decode("utf-8", errors="replace")
            stripped = output.rstrip()
            if stripped.endswith("#") or stripped.endswith(">"):
                break
        else:
            time.sleep(0.4)
    shell.close()
    return output


def parse_routes(raw):
    prefixes = set()
    for m in _ROUTE_RE.finditer(raw):
        prefixes.add(m.group(1))
    for m in _CONNECTED_RE.finditer(raw):
        prefixes.add(m.group(1))
    return prefixes


def load_baseline(path):
    data = json.loads(Path(path).read_text())
    return set(data.get("routes", []))


def save_baseline(path, routes, host):
    Path(path).write_text(
        json.dumps({"host": host, "routes": sorted(routes)}, indent=2)
    )
    logger.info("Baseline saved: %d routes → %s", len(routes), path)


def main():
    p = argparse.ArgumentParser(
        description="Detect routing table changes on a network device"
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password")
    p.add_argument("-k", "--key-file", help="SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--baseline",
        default="route_baseline.json",
        help="Baseline snapshot file (default: route_baseline.json)",
    )
    p.add_argument(
        "--save",
        action="store_true",
        help="Update baseline with current routes after comparison",
    )
    p.add_argument(
        "--command",
        default="show ip route",
        help='Routing command to run (default: "show ip route")',
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Seconds to wait for command output (default: 30)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        p.error("Provide --password or --key-file")

    logger.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = _connect(
            args.host, args.username, args.password,
            args.key_file, args.port, args.timeout,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        logger.info("Running: %s", args.command)
        raw = _run(client, args.command, args.timeout)
    finally:
        client.close()

    current = parse_routes(raw)
    if not current:
        logger.warning("No routes parsed — check --command or device output format")
        if args.verbose:
            print(raw)
        sys.exit(2)
    logger.info("Parsed %d prefixes from %s", len(current), args.host)

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        print(f"[NEW] No baseline found — capturing {len(current)} routes as baseline.")
        save_baseline(args.baseline, current, args.host)
        sys.exit(0)

    baseline = load_baseline(args.baseline)
    logger.info("Loaded %d routes from %s", len(baseline), args.baseline)

    added = sorted(current - baseline)
    removed = sorted(baseline - current)

    if not added and not removed:
        print(f"[OK] No changes on {args.host} ({len(current)} routes match baseline)")
    else:
        print(f"[CHANGED] Route differences on {args.host}:")
        if added:
            print(f"\n  Added ({len(added)}):")
            for r in added:
                print(f"    + {r}")
        if removed:
            print(f"\n  Removed ({len(removed)}):")
            for r in removed:
                print(f"    - {r}")

    if args.save:
        save_baseline(args.baseline, current, args.host)

    sys.exit(0 if not added and not removed else 1)


if __name__ == "__main__":
    main()
```