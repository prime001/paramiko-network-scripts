Interface Flap and Utilization Monitor

Polls a Cisco IOS/IOS-XE device repeatedly over a configurable window,
detecting interface state transitions (flaps) and tracking peak bandwidth
and error-counter trends across each polling cycle.

Unlike a one-shot status check this script is designed for troubleshooting
instability: run it during a maintenance window or against a suspect device
and get a summary of every flap, peak utilization, and cumulative error delta.

Usage:
    python interface_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_monitor.py -H 192.168.1.1 -u admin -p secret \\
        --interface GigabitEthernet0/1 --interval 30 --duration 300 \\
        --output csv

Prerequisites:
    pip install paramiko
    SSH access to target device with privilege level sufficient for
    'show interfaces' (typically privilege 1).
"""

import argparse
import csv
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class Snapshot:
    name: str
    status: str
    protocol: str
    input_rate: int
    output_rate: int
    input_errors: int
    output_errors: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Summary:
    name: str
    flap_count: int = 0
    peak_input_bps: int = 0
    peak_output_bps: int = 0
    baseline_input_errors: Optional[int] = None
    baseline_output_errors: Optional[int] = None
    last_input_errors: int = 0
    last_output_errors: int = 0
    last_status: str = ""


def ssh_run(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def parse_interfaces(raw: str) -> List[Snapshot]:
    snapshots: List[Snapshot] = []
    blocks = re.split(r"(?=^\S)", raw, flags=re.MULTILINE)
    for block in blocks:
        header = re.match(
            r"^(\S+) is (up|down|administratively down),\s+line protocol is (up|down)",
            block,
            re.IGNORECASE,
        )
        if not header:
            continue
        name = header.group(1)
        status = header.group(2).lower()
        protocol = header.group(3).lower()

        rate = re.search(
            r"input rate (\d+) bits/sec.*?output rate (\d+) bits/sec",
            block,
            re.DOTALL | re.IGNORECASE,
        )
        input_rate = int(rate.group(1)) if rate else 0
        output_rate = int(rate.group(2)) if rate else 0

        ie = re.search(r"(\d+) input errors", block)
        oe = re.search(r"(\d+) output errors", block)

        snapshots.append(
            Snapshot(
                name=name,
                status=status,
                protocol=protocol,
                input_rate=input_rate,
                output_rate=output_rate,
                input_errors=int(ie.group(1)) if ie else 0,
                output_errors=int(oe.group(1)) if oe else 0,
            )
        )
    return snapshots


def fmt_bps(bps: int) -> str:
    for unit, threshold in (("Gbps", 1_000_000_000), ("Mbps", 1_000_000), ("Kbps", 1_000)):
        if bps >= threshold:
            return f"{bps / threshold:.1f} {unit}"
    return f"{bps} bps"


def print_table(summaries: Dict[str, Summary]) -> None:
    hdr = f"{'Interface':<32} {'Flaps':>6} {'PeakIn':>12} {'PeakOut':>12} {'InErrDelta':>11} {'OutErrDelta':>11} {'Status':<8}"
    sep = "=" * len(hdr)
    print(f"\n{sep}\n{hdr}\n{'-' * len(hdr)}")
    for s in sorted(summaries.values(), key=lambda x: x.name):
        in_delta = s.last_input_errors - (s.baseline_input_errors or 0)
        out_delta = s.last_output_errors - (s.baseline_output_errors or 0)
        print(
            f"{s.name:<32} {s.flap_count:>6} "
            f"{fmt_bps(s.peak_input_bps):>12} {fmt_bps(s.peak_output_bps):>12} "
            f"{in_delta:>11} {out_delta:>11} {s.last_status:<8}"
        )
    print(f"{sep}\n")


def print_csv(summaries: Dict[str, Summary]) -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow(
        ["interface", "flaps", "peak_input_bps", "peak_output_bps",
         "input_error_delta", "output_error_delta", "last_status"]
    )
    for s in sorted(summaries.values(), key=lambda x: x.name):
        writer.writerow([
            s.name, s.flap_count, s.peak_input_bps, s.peak_output_bps,
            s.last_input_errors - (s.baseline_input_errors or 0),
            s.last_output_errors - (s.baseline_output_errors or 0),
            s.last_status,
        ])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor interface flaps and utilization over time on a Cisco device"
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--interface", metavar="NAME",
                   help="Filter to a single interface (partial name match)")
    p.add_argument("--interval", type=int, default=60, metavar="SEC",
                   help="Seconds between polls (default: 60)")
    p.add_argument("--duration", type=int, default=300, metavar="SEC",
                   help="Total monitoring window in seconds (default: 300)")
    p.add_argument("--output", choices=["table", "csv"], default="table",
                   help="Output format (default: table)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def run(args: argparse.Namespace) -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
        client.connect(
            args.host, port=args.port,
            username=args.username, password=args.password,
            look_for_keys=False, allow_agent=False, timeout=15,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    summaries: Dict[str, Summary] = {}
    deadline = time.monotonic() + args.duration
    poll = 0

    try:
        while time.monotonic() < deadline:
            poll += 1
            cmd = f"show interfaces {args.interface}" if args.interface else "show interfaces"
            log.info("Poll %d — %s", poll, cmd)
            raw = ssh_run(client, cmd)

            snaps = parse_interfaces(raw)
            if args.interface:
                snaps = [s for s in snaps if args.interface.lower() in s.name.lower()]

            if not snaps and poll == 1:
                log.error("No interfaces parsed — verify device type or --interface value")
                return 1

            for snap in snaps:
                if snap.name not in summaries:
                    summaries[snap.name] = Summary(
                        name=snap.name,
                        last_status=snap.status,
                        baseline_input_errors=snap.input_errors,
                        baseline_output_errors=snap.output_errors,
                    )

                s = summaries[snap.name]
                if s.last_status and s.last_status != snap.status:
                    s.flap_count += 1
                    log.warning("FLAP %s: %s → %s", snap.name, s.last_status, snap.status)
                s.last_status = snap.status
                s.peak_input_bps = max(s.peak_input_bps, snap.input_rate)
                s.peak_output_bps = max(s.peak_output_bps, snap.output_rate)
                s.last_input_errors = snap.input_errors
                s.last_output_errors = snap.output_errors

            remaining = deadline - time.monotonic()
            if remaining > args.interval:
                time.sleep(args.interval)
            else:
                break

    except KeyboardInterrupt:
        log.info("Interrupted — printing results so far")
    finally:
        client.close()

    if not summaries:
        log.warning("No data collected")
        return 1

    log.info("Done: %d poll(s) over ~%ds across %d interface(s)", poll, args.duration, len(summaries))
    if args.output == "csv":
        print_csv(summaries)
    else:
        print_table(summaries)

    flapping = [s for s in summaries.values() if s.flap_count > 0]
    if flapping:
        log.warning("%d interface(s) flapped: %s",
                    len(flapping), ", ".join(s.name for s in flapping))
    return 0


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    sys.exit(run(args))