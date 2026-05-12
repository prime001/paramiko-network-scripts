```python
"""
interface_error_monitor.py - Poll interface error counters and alert on rate thresholds.

Purpose:
    Connects to a network device via SSH and repeatedly samples interface error
    counters (input errors, output errors, CRC errors, interface resets).  Between
    samples it calculates per-second delta rates and flags any interface whose rate
    exceeds a configurable threshold.  Useful for catching intermittent link-layer
    problems that a one-shot status check would miss.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin
    python interface_error_monitor.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa \
        --interval 30 --samples 10 --threshold 0.5 --interface GigabitEthernet0/1

Prerequisites:
    pip install paramiko
    Device must support IOS-style "show interfaces" output.
"""

import argparse
import getpass
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


@dataclass
class ErrorSnapshot:
    timestamp: float
    input_errors: int = 0
    output_errors: int = 0
    crc_errors: int = 0
    resets: int = 0


@dataclass
class InterfaceStats:
    name: str
    history: List[ErrorSnapshot] = field(default_factory=list)

    def record(self, snap: ErrorSnapshot) -> None:
        self.history.append(snap)
        if len(self.history) > 2:
            self.history.pop(0)

    def rates(self) -> Optional[Dict[str, float]]:
        if len(self.history) < 2:
            return None
        old, new = self.history[0], self.history[1]
        elapsed = new.timestamp - old.timestamp
        if elapsed <= 0:
            return None
        return {
            "input_errors": (new.input_errors - old.input_errors) / elapsed,
            "output_errors": (new.output_errors - old.output_errors) / elapsed,
            "crc_errors": (new.crc_errors - old.crc_errors) / elapsed,
            "resets": (new.resets - old.resets) / elapsed,
        }


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def parse_error_counters(output: str) -> Dict[str, ErrorSnapshot]:
    snapshots: Dict[str, ErrorSnapshot] = {}
    current = None
    ts = time.time()

    iface_re = re.compile(r"^(\S+) is (?:up|down|administratively down)", re.IGNORECASE)
    in_err_re = re.compile(r"(\d+) input errors", re.IGNORECASE)
    out_err_re = re.compile(r"(\d+) output errors", re.IGNORECASE)
    crc_re = re.compile(r"(\d+) CRC", re.IGNORECASE)
    reset_re = re.compile(r"(\d+) interface resets", re.IGNORECASE)

    for line in output.splitlines():
        m = iface_re.match(line)
        if m:
            current = m.group(1)
            snapshots[current] = ErrorSnapshot(timestamp=ts)
            continue
        if current is None:
            continue
        snap = snapshots[current]
        if (m := in_err_re.search(line)):
            snap.input_errors = int(m.group(1))
        if (m := out_err_re.search(line)):
            snap.output_errors = int(m.group(1))
        if (m := crc_re.search(line)):
            snap.crc_errors = int(m.group(1))
        if (m := reset_re.search(line)):
            snap.resets = int(m.group(1))

    return snapshots


def print_report(all_stats: Dict[str, "InterfaceStats"], threshold: float) -> bool:
    rows = []
    for name, iface in sorted(all_stats.items()):
        r = iface.rates()
        if r is None:
            continue
        rows.append((name, r, any(v > threshold for v in r.values())))

    if not rows:
        log.info("Awaiting second sample for rate calculation.")
        return False

    print(
        f"\n{'Interface':<32} {'In Err/s':>10} {'Out Err/s':>10}"
        f" {'CRC/s':>8} {'Resets/s':>10}  Status"
    )
    print("-" * 84)
    breached = False
    for name, r, over in rows:
        flag = "  *** ALERT ***" if over else ""
        if over:
            breached = True
        print(
            f"{name:<32} {r['input_errors']:>10.2f} {r['output_errors']:>10.2f}"
            f" {r['crc_errors']:>8.2f} {r['resets']:>10.2f}{flag}"
        )
    return breached


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor interface error rates and alert when thresholds are exceeded."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", help="Path to SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--interval", type=int, default=60,
        help="Seconds between polls (default: 60)"
    )
    parser.add_argument(
        "--samples", type=int, default=5,
        help="Poll cycles before exit; 0 = run until Ctrl-C (default: 5)"
    )
    parser.add_argument(
        "--threshold", type=float, default=1.0,
        help="Errors-per-second rate that triggers an alert (default: 1.0)"
    )
    parser.add_argument(
        "--interface", help="Restrict monitoring to interfaces matching this substring"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs: dict = {
            "hostname": args.host,
            "port": args.port,
            "username": args.username,
            "timeout": 10,
        }
        if args.key:
            connect_kwargs["key_filename"] = args.key
        else:
            connect_kwargs["password"] = password

        log.info("Connecting to %s:%d", args.host, args.port)
        client.connect(**connect_kwargs)
        cycle_limit = args.samples if args.samples else float("inf")
        log.info(
            "Connected. Polling every %ds, %s cycles, alert threshold %.2f err/s.",
            args.interval,
            args.samples if args.samples else "unlimited",
            args.threshold,
        )

        all_stats: Dict[str, InterfaceStats] = {}
        cycle = 0

        while cycle < cycle_limit:
            try:
                output = run_command(client, "show interfaces")
            except Exception as exc:
                log.error("Command failed: %s", exc)
                break

            snapshots = parse_error_counters(output)
            if args.interface:
                snapshots = {
                    k: v for k, v in snapshots.items()
                    if args.interface.lower() in k.lower()
                }

            for name, snap in snapshots.items():
                if name not in all_stats:
                    all_stats[name] = InterfaceStats(name=name)
                all_stats[name].record(snap)

            cycle += 1
            log.info("Cycle %d — %d interfaces sampled.", cycle, len(snapshots))
            if print_report(all_stats, args.threshold):
                log.warning(
                    "Alert: one or more interfaces exceeded %.2f err/s.", args.threshold
                )

            if cycle < cycle_limit:
                time.sleep(args.interval)

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Interrupted by user.")
    finally:
        client.close()
        log.info("Connection closed.")


if __name__ == "__main__":
    main()
```