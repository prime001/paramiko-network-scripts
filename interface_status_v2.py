interface_error_monitor.py — Poll interface error counters and alert on increments.

Connects to a network device via SSH and samples `show interfaces` output repeatedly
at a configurable interval.  Between samples it computes the delta for each error
counter (CRC, input errors, output drops, runts, giants) and flags any interface
where a counter grew by at least --threshold counts.

Useful for catching intermittent errors that clear before a one-shot status check
would reveal them — e.g. a flapping SFP that's throwing CRC errors every 45 seconds.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \
        --interval 30 --count 10 --threshold 5
    python interface_error_monitor.py -H 192.168.1.1 -u admin \
        --interface GigabitEthernet0/1 --verbose

Prerequisites:
    pip install paramiko
    SSH must be enabled on the device; read-only privilege is sufficient.
    Tested against IOS/IOS-XE `show interfaces` output format.
"""

import argparse
import getpass
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

import paramiko

logging.basicConfig(
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

COUNTER_PATTERNS: Dict[str, re.Pattern] = {
    "input_errors": re.compile(r"(\d+) input errors"),
    "crc":          re.compile(r"(\d+) CRC"),
    "output_drops": re.compile(r"(\d+) output drops"),
    "input_drops":  re.compile(r"(\d+) input drops"),
    "giants":       re.compile(r"(\d+) giants"),
    "runts":        re.compile(r"(\d+) runts"),
}


@dataclass
class IfaceSnapshot:
    name: str
    counters: Dict[str, int] = field(default_factory=dict)


def ssh_connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
    )
    return client


def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 20) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("Device stderr: %s", err)
    return output


def parse_counters(raw: str) -> Dict[str, IfaceSnapshot]:
    """Parse `show interfaces` output into per-interface error counters."""
    snapshots: Dict[str, IfaceSnapshot] = {}

    # Each interface block starts on a non-indented line matching '<Name> is ...'
    blocks = re.split(r"\n(?=\S)", raw)
    for block in blocks:
        header = re.match(r"^(\S+)\s+is\s+", block)
        if not header:
            continue
        name = header.group(1)
        counters: Dict[str, int] = {}
        for key, pattern in COUNTER_PATTERNS.items():
            m = pattern.search(block)
            if m:
                counters[key] = int(m.group(1))
        if counters:
            snapshots[name] = IfaceSnapshot(name=name, counters=counters)

    return snapshots


def collect(client: paramiko.SSHClient, interface: Optional[str]) -> Dict[str, IfaceSnapshot]:
    cmd = f"show interfaces {interface}" if interface else "show interfaces"
    return parse_counters(ssh_exec(client, cmd))


def check_deltas(
    prev: Dict[str, IfaceSnapshot],
    curr: Dict[str, IfaceSnapshot],
    threshold: int,
) -> bool:
    """Log any counter that grew by >= threshold since the last sample."""
    flagged = False
    for name, snap in curr.items():
        if name not in prev:
            continue
        deltas = {
            k: snap.counters.get(k, 0) - prev[name].counters.get(k, 0)
            for k in snap.counters
            if snap.counters.get(k, 0) - prev[name].counters.get(k, 0) >= threshold
        }
        if deltas:
            flagged = True
            detail = "  ".join(f"{k}=+{v}" for k, v in deltas.items())
            log.warning("ERRORS DETECTED  %-40s  %s", name, detail)
    return flagged


def run(args: argparse.Namespace) -> int:
    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        client = ssh_connect(args.host, args.port, args.username, password)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        return 1

    try:
        log.info(
            "Monitoring: interval=%ds  rounds=%d  threshold=%d  interface=%s",
            args.interval,
            args.count,
            args.threshold,
            args.interface or "all",
        )
        baseline = collect(client, args.interface)
        log.info("Baseline captured (%d interface(s) with counters)", len(baseline))

        any_flagged = False
        for i in range(1, args.count + 1):
            time.sleep(args.interval)
            current = collect(client, args.interface)
            log.info("Poll %d/%d", i, args.count)
            if check_deltas(baseline, current, args.threshold):
                any_flagged = True
            baseline = current

        if not any_flagged:
            log.info("No error increments >= %d detected across %d poll(s).",
                     args.threshold, args.count)

    except KeyboardInterrupt:
        log.info("Stopped by user")
    except Exception as exc:
        log.error("Monitoring error: %s", exc)
        return 1
    finally:
        client.close()

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Poll SSH device for interface error counter increments. "
            "Flags interfaces where counters grow between samples."
        )
    )
    parser.add_argument("-H", "--host",      required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username",  required=True, help="SSH username")
    parser.add_argument("-p", "--password",  default=None,  help="SSH password (prompted if omitted)")
    parser.add_argument("--port",      type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--interface", default=None,
                        help="Restrict to one interface, e.g. GigabitEthernet0/1")
    parser.add_argument("--interval",  type=int, default=60,
                        help="Seconds between polls (default: 60)")
    parser.add_argument("--count",     type=int, default=5,
                        help="Number of polling rounds after baseline (default: 5)")
    parser.add_argument("--threshold", type=int, default=1,
                        help="Minimum counter delta to flag as an error (default: 1)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug-level logging")
    return parser.parse_args()


if __name__ == "__main__":
    _args = parse_args()
    if _args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    sys.exit(run(_args))