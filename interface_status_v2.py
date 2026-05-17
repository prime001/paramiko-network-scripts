```python
"""
Interface error counter monitor for Cisco IOS devices.

Connects via SSH (paramiko) and parses 'show interfaces' output to extract
per-interface error counters (CRC, input errors, output drops, resets).
Exits non-zero if any counter exceeds the configured threshold — suitable
for use in monitoring pipelines or cron-based alerting.

Usage:
    python interface_errors.py -d 192.168.1.1 -u admin -p secret
    python interface_errors.py -d 10.0.0.1 -u admin -p secret --threshold 100 --csv

Prerequisites:
    pip install paramiko
"""

import argparse
import csv
import logging
import re
import sys
import getpass
from dataclasses import dataclass, fields
from typing import List

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    input_errors: int
    crc: int
    output_drops: int
    resets: int

    def exceeds(self, threshold: int) -> bool:
        return any(
            getattr(self, f.name) > threshold
            for f in fields(self)
            if f.name != "name"
        )


def ssh_run(host: str, port: int, username: str, password: str, command: str) -> str:
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
        _, stdout, stderr = client.exec_command(command, timeout=30)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.debug("stderr: %s", err)
        return output
    finally:
        client.close()


def parse_interface_errors(raw: str) -> List[InterfaceErrors]:
    results = []
    blocks = re.split(r"(?=^\S)", raw, flags=re.MULTILINE)

    for block in blocks:
        name_match = re.match(r"^(\S+) is ", block)
        if not name_match:
            continue
        name = name_match.group(1)

        def extract(pattern: str) -> int:
            m = re.search(pattern, block)
            return int(m.group(1)) if m else 0

        results.append(InterfaceErrors(
            name=name,
            input_errors=extract(r"(\d+) input errors"),
            crc=extract(r"(\d+) CRC"),
            output_drops=extract(r"(\d+) output drops"),
            resets=extract(r"(\d+) resets"),
        ))

    return results


def print_table(interfaces: List[InterfaceErrors], threshold: int) -> None:
    header = f"{'Interface':<35} {'InErr':>8} {'CRC':>8} {'OutDrop':>8} {'Resets':>8}  {'ALERT':>6}"
    print(header)
    print("-" * len(header))
    for iface in interfaces:
        alert = "YES" if iface.exceeds(threshold) else ""
        print(
            f"{iface.name:<35} {iface.input_errors:>8} {iface.crc:>8} "
            f"{iface.output_drops:>8} {iface.resets:>8}  {alert:>6}"
        )


def write_csv(interfaces: List[InterfaceErrors], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["interface", "input_errors", "crc", "output_drops", "resets"])
        for iface in interfaces:
            writer.writerow([
                iface.name, iface.input_errors, iface.crc,
                iface.output_drops, iface.resets,
            ])
    log.info("CSV written to %s", path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect interface error counters from a Cisco IOS device"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None,
                        help="Password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--threshold", type=int, default=0,
        help="Alert if any counter exceeds this value (default: 0 = any non-zero)"
    )
    parser.add_argument("--csv", metavar="FILE", help="Write results to CSV file")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        raw = ssh_run(args.device, args.port, args.username, password, "show interfaces")
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 2
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        return 2

    interfaces = parse_interface_errors(raw)
    if not interfaces:
        log.warning("No interface data parsed — check device output format")
        return 1

    print_table(interfaces, args.threshold)

    if args.csv:
        write_csv(interfaces, args.csv)

    exceeded = [i for i in interfaces if i.exceeds(args.threshold)]
    if exceeded:
        log.warning(
            "%d interface(s) exceed threshold %d: %s",
            len(exceeded), args.threshold,
            ", ".join(i.name for i in exceeded),
        )
        return 1

    log.info("All %d interfaces within threshold", len(interfaces))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```