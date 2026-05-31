```python
"""
interface_status_v3.py - Interface error counter and utilization monitor.

Connects to a Cisco IOS/IOS-XE device via Paramiko and collects interface
error counters (CRC, input errors, output drops, resets). Optionally polls
twice to calculate counter deltas, surfacing interfaces actively accumulating
errors rather than just reporting lifetime totals.

Usage:
    python interface_status_v3.py -d 192.168.1.1 -u admin -p secret
    python interface_status_v3.py -d 192.168.1.1 -u admin -p secret --poll 30
    python interface_status_v3.py -d 192.168.1.1 -u admin -p secret --threshold 0 --json

Prerequisites:
    pip install paramiko
"""

import argparse
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

COUNTER_PATTERN = re.compile(
    r"^(?P<iface>\S+) is (?P<state>up|down|administratively down)",
    re.MULTILINE,
)
INPUT_ERRORS = re.compile(r"(\d+) input errors")
CRC_ERRORS = re.compile(r"(\d+) CRC")
OUTPUT_DROPS = re.compile(r"(\d+) output drops")
RESETS = re.compile(r"(\d+) interface resets")
RUNTS = re.compile(r"(\d+) runts")
GIANTS = re.compile(r"(\d+) giants")


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
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


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def _extract(pattern: re.Pattern, text: str) -> int:
    m = pattern.search(text)
    return int(m.group(1)) if m else 0


def parse_interface_counters(raw: str) -> dict:
    counters = {}
    blocks = re.split(r"\n(?=\S)", raw)
    for block in blocks:
        m = COUNTER_PATTERN.match(block)
        if not m:
            continue
        iface = m.group("iface")
        state = m.group("state")
        counters[iface] = {
            "state": state,
            "input_errors": _extract(INPUT_ERRORS, block),
            "crc": _extract(CRC_ERRORS, block),
            "output_drops": _extract(OUTPUT_DROPS, block),
            "resets": _extract(RESETS, block),
            "runts": _extract(RUNTS, block),
            "giants": _extract(GIANTS, block),
        }
    return counters


def compute_delta(first: dict, second: dict) -> dict:
    delta = {}
    all_keys = set(first) | set(second)
    counter_fields = ("input_errors", "crc", "output_drops", "resets", "runts", "giants")
    for iface in all_keys:
        if iface not in first or iface not in second:
            continue
        entry = {"state": second[iface]["state"]}
        for field in counter_fields:
            entry[field] = second[iface][field] - first[iface].get(field, 0)
        delta[iface] = entry
    return delta


def filter_errors(counters: dict, threshold: int) -> dict:
    counter_fields = ("input_errors", "crc", "output_drops", "resets", "runts", "giants")
    return {
        iface: data
        for iface, data in counters.items()
        if any(data.get(f, 0) > threshold for f in counter_fields)
    }


def print_table(counters: dict, delta_mode: bool) -> None:
    header = f"{'Interface':<25} {'State':<8} {'InErr':>7} {'CRC':>7} {'OutDrop':>8} {'Resets':>7} {'Runts':>6} {'Giants':>7}"
    label = "DELTA" if delta_mode else "TOTALS"
    print(f"\n--- Interface Error Counters ({label}) ---")
    print(header)
    print("-" * len(header))
    for iface, data in sorted(counters.items()):
        print(
            f"{iface:<25} {data['state']:<8} "
            f"{data['input_errors']:>7} {data['crc']:>7} "
            f"{data['output_drops']:>8} {data['resets']:>7} "
            f"{data['runts']:>6} {data['giants']:>7}"
        )
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor interface error counters via SSH")
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--poll",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Poll interval in seconds; if >0, shows counter deltas between two samples",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=0,
        help="Only show interfaces with counters above this value (default: 0 = any error)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--all", action="store_true", help="Show all interfaces, not just those with errors")
    args = parser.parse_args()

    try:
        log.info("Connecting to %s", args.device)
        client = ssh_connect(args.device, args.username, args.password, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Collecting interface counters (sample 1)")
        raw1 = run_command(client, "show interfaces")
        first = parse_interface_counters(raw1)

        if args.poll > 0:
            log.info("Waiting %d seconds before second sample...", args.poll)
            time.sleep(args.poll)
            log.info("Collecting interface counters (sample 2)")
            raw2 = run_command(client, "show interfaces")
            second = parse_interface_counters(raw2)
            result = compute_delta(first, second)
            delta_mode = True
        else:
            result = first
            delta_mode = False
    finally:
        client.close()

    if not args.all:
        result = filter_errors(result, args.threshold)
        if not result:
            log.info("No interfaces exceed error threshold of %d", args.threshold)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_table(result, delta_mode)


if __name__ == "__main__":
    main()
```