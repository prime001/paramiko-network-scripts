```python
"""
Route Change Detector - Network Automation Script

Purpose:
    Connects to a network device via SSH using paramiko, retrieves the IP routing
    table, and compares it against a saved JSON baseline to detect added or removed
    routes. Designed for post-change validation and routing audit workflows.

Usage:
    # Save a baseline snapshot of the current routing table
    python route_monitor.py --host 192.168.1.1 --username admin --save-baseline

    # Compare live routing table against the saved baseline
    python route_monitor.py --host 192.168.1.1 --username admin --compare

    # Print the current routing table without comparison
    python route_monitor.py --host 192.168.1.1 --username admin

Prerequisites:
    pip install paramiko
    SSH access to target device (Cisco IOS / IOS-XE compatible)
    Device must support 'show ip route' command
"""

import argparse
import getpass
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

ROUTE_PATTERN = re.compile(
    r"^[A-Z*>i]\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?)\s",
    re.MULTILINE,
)
DEFAULT_BASELINE = "route_baseline.json"


def ssh_connect(host: str, username: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("SSH connection failed: %s", exc)
        sys.exit(1)
    return client


def fetch_routing_table(client: paramiko.SSHClient) -> str:
    try:
        _, stdout, stderr = client.exec_command("show ip route", timeout=30)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.warning("Device stderr: %s", err)
        if not output.strip():
            log.error("Empty response from device — verify command support")
            sys.exit(1)
        return output
    except paramiko.SSHException as exc:
        log.error("Command execution failed: %s", exc)
        sys.exit(1)


def extract_prefixes(routing_output: str) -> set[str]:
    return set(ROUTE_PATTERN.findall(routing_output))


def save_baseline(host: str, prefixes: set[str], baseline_path: str) -> None:
    data = {
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prefix_count": len(prefixes),
        "prefixes": sorted(prefixes),
    }
    Path(baseline_path).write_text(json.dumps(data, indent=2))
    log.info("Baseline saved: %d prefixes → %s", len(prefixes), baseline_path)


def load_baseline(baseline_path: str) -> dict:
    path = Path(baseline_path)
    if not path.exists():
        log.error("Baseline file not found: %s  (run with --save-baseline first)", baseline_path)
        sys.exit(1)
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        log.error("Corrupt baseline file: %s", exc)
        sys.exit(1)


def compare_routes(baseline: set[str], current: set[str]) -> int:
    added = current - baseline
    removed = baseline - current

    if not added and not removed:
        print("No routing changes detected.")
        return 0

    if added:
        print(f"\nADDED ({len(added)} route{'s' if len(added) != 1 else ''}):")
        for prefix in sorted(added):
            print(f"  + {prefix}")

    if removed:
        print(f"\nREMOVED ({len(removed)} route{'s' if len(removed) != 1 else ''}):")
        for prefix in sorted(removed):
            print(f"  - {prefix}")

    print(f"\nSummary: +{len(added)} added, -{len(removed)} removed")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect routing table changes by comparing against a saved baseline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--save-baseline", action="store_true",
                        help="Snapshot current routing table as baseline")
    parser.add_argument("--compare", action="store_true",
                        help="Compare live routing table against saved baseline")
    parser.add_argument("--baseline-file", default=DEFAULT_BASELINE,
                        help="Path to baseline JSON file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    log.info("Connecting to %s:%d", args.host, args.port)
    client = ssh_connect(args.host, args.username, password, args.port)

    try:
        log.info("Fetching routing table from %s", args.host)
        raw_output = fetch_routing_table(client)
        current_prefixes = extract_prefixes(raw_output)
        log.info("Parsed %d prefixes from routing table", len(current_prefixes))

        if args.save_baseline:
            save_baseline(args.host, current_prefixes, args.baseline_file)
        elif args.compare:
            baseline_data = load_baseline(args.baseline_file)
            baseline_prefixes = set(baseline_data["prefixes"])
            print(f"Baseline : {args.baseline_file}  [{baseline_data['timestamp']}]  "
                  f"{baseline_data['prefix_count']} prefixes")
            print(f"Current  : {args.host}  {len(current_prefixes)} prefixes")
            sys.exit(compare_routes(baseline_prefixes, current_prefixes))
        else:
            print(raw_output)
    finally:
        client.close()
```