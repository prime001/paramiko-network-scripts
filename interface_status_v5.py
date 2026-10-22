```python
"""
interface_error_monitor.py - Network interface error rate monitor via SSH.

Polls a Cisco IOS device's interface counters at configurable intervals,
computes per-interval error rates, and flags any interface that exceeds
configurable thresholds for CRC errors, input errors, or output drops.
Useful for catching transient link issues that clear before you check manually.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 10.0.0.1 -u admin -k ~/.ssh/id_rsa \\
        --interval 30 --samples 5 --threshold 0.001 --interface GigabitEthernet0/1

Prerequisites:
    pip install paramiko
    SSH access to a Cisco IOS device; privilege level 1 is sufficient.
"""

import argparse
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
class InterfaceCounters:
    name: str
    input_packets: int = 0
    input_errors: int = 0
    crc: int = 0
    output_packets: int = 0
    output_drops: int = 0
    resets: int = 0


@dataclass
class ErrorRateResult:
    name: str
    crc_rate: float = 0.0
    input_error_rate: float = 0.0
    output_drop_rate: float = 0.0
    reset_delta: int = 0
    flagged: bool = False
    reasons: List[str] = field(default_factory=list)


def ssh_connect(
    host: str, port: int, username: str,
    password: Optional[str], key_file: Optional[str],
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": host, "port": port, "username": username,
        "timeout": 30, "look_for_keys": False, "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
        kwargs["look_for_keys"] = True
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key-file")
    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        raise
    return client


def run_command(client: paramiko.SSHClient, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=30)
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return stdout.read().decode(errors="replace")


def parse_counters(output: str) -> Dict[str, InterfaceCounters]:
    counters: Dict[str, InterfaceCounters] = {}
    current: Optional[InterfaceCounters] = None

    for line in output.splitlines():
        m = re.match(r'^(\S+) is (?:up|down|administratively down)', line)
        if m:
            current = InterfaceCounters(name=m.group(1))
            counters[current.name] = current
            continue
        if current is None:
            continue
        for pattern, attr in [
            (r'(\d+) packets input', 'input_packets'),
            (r'(\d+) input errors', 'input_errors'),
            (r'(\d+) CRC', 'crc'),
            (r'(\d+) packets output', 'output_packets'),
            (r'(\d+) output drops', 'output_drops'),
            (r'(\d+) interface resets', 'resets'),
        ]:
            m = re.search(pattern, line)
            if m:
                setattr(current, attr, int(m.group(1)))

    return counters


def compute_rates(
    baseline: Dict[str, InterfaceCounters],
    current: Dict[str, InterfaceCounters],
    threshold: float,
) -> List[ErrorRateResult]:
    results = []
    for name, curr in current.items():
        if name not in baseline:
            continue
        base = baseline[name]
        in_delta = max(curr.input_packets - base.input_packets, 1)
        out_delta = max(curr.output_packets - base.output_packets, 1)

        result = ErrorRateResult(
            name=name,
            crc_rate=max((curr.crc - base.crc) / in_delta, 0.0),
            input_error_rate=max((curr.input_errors - base.input_errors) / in_delta, 0.0),
            output_drop_rate=max((curr.output_drops - base.output_drops) / out_delta, 0.0),
            reset_delta=max(curr.resets - base.resets, 0),
        )
        if result.crc_rate > threshold:
            result.flagged = True
            result.reasons.append(f"CRC rate {result.crc_rate:.4%}")
        if result.input_error_rate > threshold:
            result.flagged = True
            result.reasons.append(f"input error rate {result.input_error_rate:.4%}")
        if result.output_drop_rate > threshold:
            result.flagged = True
            result.reasons.append(f"output drop rate {result.output_drop_rate:.4%}")
        if result.reset_delta > 0:
            result.flagged = True
            result.reasons.append(f"{result.reset_delta} reset(s)")
        results.append(result)
    return results


def print_report(rates: List[ErrorRateResult], sample_num: int, total: int) -> None:
    flagged = [r for r in rates if r.flagged]
    print(f"\n--- Sample {sample_num}/{total} ---")
    if flagged:
        print(f"FLAGGED ({len(flagged)}):")
        for r in sorted(flagged, key=lambda x: x.name):
            print(f"  {r.name}: {', '.join(r.reasons)}")
    else:
        print(f"All {len(rates)} interface(s) within threshold.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Monitor interface error rates on a Cisco IOS device."
    )
    parser.add_argument("-H", "--host", required=True)
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("-k", "--key-file", default=None)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--interval", type=int, default=60,
                        help="Seconds between samples (default: 60)")
    parser.add_argument("--samples", type=int, default=3,
                        help="Number of polling intervals (default: 3)")
    parser.add_argument("--threshold", type=float, default=0.001,
                        help="Error fraction threshold, e.g. 0.001 = 0.1%% (default: 0.001)")
    parser.add_argument("--interface", default=None,
                        help="Restrict to one interface, e.g. GigabitEthernet0/1")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        parser.error("Provide --password or --key-file")

    try:
        client = ssh_connect(args.host, args.port, args.username, args.password, args.key_file)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        return 1

    cmd = f"show interfaces {args.interface}" if args.interface else "show interfaces"

    try:
        log.info("Baseline sample from %s ...", args.host)
        baseline = parse_counters(run_command(client, cmd))
        log.info("Baseline: %d interface(s). Polling every %ds for %d sample(s).",
                 len(baseline), args.interval, args.samples)

        for i in range(1, args.samples + 1):
            time.sleep(args.interval)
            current = parse_counters(run_command(client, cmd))
            rates = compute_rates(baseline, current, args.threshold)
            print_report(rates, i, args.samples)
            baseline = current

    except KeyboardInterrupt:
        log.info("Stopped by user.")
    except Exception as exc:
        log.error("Monitoring error: %s", exc)
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
```