The user's explicit instructions override the brainstorming skill here: they asked for "Output ONLY the script content, no markdown fences, no explanation." The task is fully specified with no design ambiguity. Proceeding directly.

```python
"""
Interface Error Monitor - Network Automation Script

Purpose:
    Polls interface error counters (CRC, input/output errors, resets, carrier
    transitions) across one or more polling intervals and alerts when deltas
    exceed a configurable threshold. Useful for detecting intermittent errors
    and link instability that a single-shot status check would miss.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 10.0.0.1 -u admin -k ~/.ssh/id_rsa \\
        --interval 30 --count 5 --threshold 50
    python interface_error_monitor.py -H router1 -u admin -p pass --json

Prerequisites:
    pip install paramiko
    SSH access to a Cisco IOS/NX-OS device; 'show interfaces' must be available.
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class InterfaceCounters:
    name: str
    is_up: bool = True
    input_errors: int = 0
    crc: int = 0
    output_errors: int = 0
    resets: int = 0
    flaps: int = 0


def ssh_connect(
    host: str,
    port: int,
    username: str,
    password: Optional[str],
    key_file: Optional[str],
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {"hostname": host, "port": port, "username": username, "timeout": 30}
    if key_file:
        kwargs["key_filename"] = key_file
    elif password:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    try:
        client.connect(**kwargs)
        return client
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except Exception as exc:
        logger.error("Cannot connect to %s:%d — %s", host, port, exc)
        sys.exit(1)


def run_command(client: paramiko.SSHClient, command: str) -> str:
    try:
        _, stdout, _ = client.exec_command(command, timeout=30)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.error("Command failed: %s", exc)
        return ""


def parse_counters(output: str) -> Dict[str, InterfaceCounters]:
    counters: Dict[str, InterfaceCounters] = {}
    iface: Optional[str] = None

    for line in output.splitlines():
        m = re.match(r"^(\S+) is (up|down)", line)
        if m:
            iface = m.group(1)
            counters[iface] = InterfaceCounters(name=iface, is_up=(m.group(2) == "up"))
            continue

        if iface is None:
            continue

        m = re.search(r"(\d+) input errors.*?(\d+) CRC", line)
        if m:
            counters[iface].input_errors = int(m.group(1))
            counters[iface].crc = int(m.group(2))

        m = re.search(r"(\d+) output errors", line)
        if m:
            counters[iface].output_errors = int(m.group(1))

        m = re.search(r"(\d+) interface resets", line)
        if m:
            counters[iface].resets = int(m.group(1))

        m = re.search(r"(\d+) carrier transitions", line)
        if m:
            counters[iface].flaps = int(m.group(1))

    return counters


def check_deltas(
    baseline: Dict[str, InterfaceCounters],
    current: Dict[str, InterfaceCounters],
    threshold: int,
) -> List[str]:
    alerts: List[str] = []
    for name, curr in current.items():
        base = baseline.get(name)
        if base is None:
            continue
        checks = [
            ("CRC errors", curr.crc - base.crc, curr.crc),
            ("input errors", curr.input_errors - base.input_errors, curr.input_errors),
            ("output errors", curr.output_errors - base.output_errors, curr.output_errors),
        ]
        for label, delta, total in checks:
            if delta > threshold:
                alerts.append(f"  {name}: +{delta} {label} (total {total})")
        delta_flaps = curr.flaps - base.flaps
        if delta_flaps > 0:
            alerts.append(f"  {name}: +{delta_flaps} carrier transitions (total {curr.flaps})")
        if curr.is_up != base.is_up:
            state = "UP" if curr.is_up else "DOWN"
            alerts.append(f"  {name}: link state → {state}")
    return alerts


def format_table(counters: Dict[str, InterfaceCounters]) -> str:
    hdr = f"{'Interface':<28} {'St':<5} {'InErr':>8} {'CRC':>7} {'OutErr':>8} {'Rst':>6} {'Flaps':>7}"
    rows = [hdr, "-" * len(hdr)]
    for c in sorted(counters.values(), key=lambda x: x.name):
        state = "up" if c.is_up else "DOWN"
        rows.append(
            f"{c.name:<28} {state:<5} {c.input_errors:>8} {c.crc:>7} "
            f"{c.output_errors:>8} {c.resets:>6} {c.flaps:>7}"
        )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor interface error counters and carrier transitions"
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("-k", "--key-file", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--interval", type=int, default=60, help="Seconds between polls (default: 60)"
    )
    parser.add_argument(
        "--count", type=int, default=3, help="Poll iterations; 0=run until Ctrl+C (default: 3)"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Error delta that triggers an alert (default: 10)",
    )
    parser.add_argument("--json", action="store_true", help="Dump final counters as JSON")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    logger.info("Connecting to %s:%d", args.host, args.port)
    client = ssh_connect(args.host, args.port, args.username, args.password, args.key_file)

    baseline: Optional[Dict[str, InterfaceCounters]] = None
    poll = 0

    try:
        while args.count == 0 or poll < args.count:
            raw = run_command(client, "show interfaces")
            if not raw:
                logger.error("Empty response; aborting")
                break

            current = parse_counters(raw)

            if baseline is None:
                baseline = current
                print(f"\n=== Baseline — {len(current)} interfaces ===")
                print(format_table(current))
            else:
                alerts = check_deltas(baseline, current, args.threshold)
                print(f"\n=== Poll {poll + 1} (Δ threshold={args.threshold}) ===")
                if alerts:
                    print("ALERTS:")
                    print("\n".join(alerts))
                else:
                    print("No threshold crossings.")
                baseline = current

            poll += 1

            if args.count == 0 or poll < args.count:
                logger.info("Next poll in %ds — Ctrl+C to stop", args.interval)
                time.sleep(args.interval)

    except KeyboardInterrupt:
        logger.info("Stopped by user")
    finally:
        client.close()

    if args.json and baseline:
        payload = {
            name: {
                "is_up": c.is_up,
                "input_errors": c.input_errors,
                "crc": c.crc,
                "output_errors": c.output_errors,
                "resets": c.resets,
                "flaps": c.flaps,
            }
            for name, c in sorted(baseline.items())
        }
        print("\n" + json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
```