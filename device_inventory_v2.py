```python
#!/usr/bin/env python3
"""
device_inventory.py — Hardware and software asset inventory collector for network devices.

Connects to one or more Cisco IOS/IOS-XE devices via SSH and collects structured
inventory data: hostname, platform, software version, serial numbers, uptime, and
memory utilization. Results are written to CSV or JSON for asset tracking.

Usage:
    python device_inventory.py -d 192.168.1.1 -u admin -p secret
    python device_inventory.py --host-file hosts.txt -u admin --format json -o inventory.json
    python device_inventory.py -d 10.0.0.1 -u admin -p secret --format csv -o report.csv

Prerequisites:
    pip install paramiko
    SSH access to target devices with 'show version' and 'show inventory' privileges.
"""

import argparse
import csv
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)


@dataclass
class DeviceRecord:
    host: str
    hostname: str = ""
    platform: str = ""
    software_version: str = ""
    serial_number: str = ""
    uptime: str = ""
    total_memory_kb: int = 0
    free_memory_kb: int = 0
    memory_used_pct: float = 0.0
    collected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error: str = ""


def _run_command(channel: paramiko.Channel, command: str, timeout: int = 10) -> str:
    channel.send(command + "\n")
    output = ""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if output.rstrip().endswith("#") or output.rstrip().endswith(">"):
                break
        time.sleep(0.1)
    return output


def collect_inventory(host: str, username: str, password: str,
                      port: int = 22, timeout: int = 30) -> DeviceRecord:
    record = DeviceRecord(host=host)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log.info("Connecting to %s", host)
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, look_for_keys=False, allow_agent=False)

        channel = client.invoke_shell(width=200, height=50)
        import time; time.sleep(1)
        channel.recv(65535)  # drain banner

        _run_command(channel, "terminal length 0")

        version_output = _run_command(channel, "show version")
        _parse_show_version(version_output, record)

        inventory_output = _run_command(channel, "show inventory")
        _parse_show_inventory(inventory_output, record)

        channel.close()
        log.info("Collected inventory from %s (%s)", host, record.hostname or "unknown")

    except paramiko.AuthenticationException:
        record.error = "Authentication failed"
        log.error("Authentication failed for %s", host)
    except paramiko.SSHException as exc:
        record.error = f"SSH error: {exc}"
        log.error("SSH error on %s: %s", host, exc)
    except OSError as exc:
        record.error = f"Connection error: {exc}"
        log.error("Cannot reach %s: %s", host, exc)
    finally:
        client.close()

    return record


def _parse_show_version(output: str, record: DeviceRecord) -> None:
    m = re.search(r"^(\S+)\s+uptime is (.+)$", output, re.MULTILINE)
    if m:
        record.hostname = m.group(1)
        record.uptime = m.group(2).strip()

    m = re.search(r"Cisco IOS.*?Version\s+(\S+)", output)
    if m:
        record.software_version = m.group(1).rstrip(",")

    m = re.search(r"Cisco\s+(\S+(?:\s+\S+)?)\s+(?:processor|chassis)", output, re.IGNORECASE)
    if m:
        record.platform = m.group(1)

    m = re.search(r"(\d+)K[/ ]+bytes of.*?memory.*?(\d+)K.*?free", output, re.IGNORECASE)
    if m:
        record.total_memory_kb = int(m.group(1))
        record.free_memory_kb = int(m.group(2))
    else:
        m = re.search(r"with\s+(\d+)/(\d+)\s+bytes of memory", output, re.IGNORECASE)
        if m:
            record.total_memory_kb = int(m.group(1)) // 1024
            record.free_memory_kb = int(m.group(2)) // 1024

    if record.total_memory_kb > 0:
        used = record.total_memory_kb - record.free_memory_kb
        record.memory_used_pct = round(used / record.total_memory_kb * 100, 1)


def _parse_show_inventory(output: str, record: DeviceRecord) -> None:
    if record.serial_number:
        return
    m = re.search(r'SN:\s+(\S+)', output)
    if m:
        record.serial_number = m.group(1)


def write_csv(records: List[DeviceRecord], path: str) -> None:
    if not records:
        return
    fieldnames = list(asdict(records[0]).keys())
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(asdict(r) for r in records)
    log.info("CSV written to %s", path)


def write_json(records: List[DeviceRecord], path: str) -> None:
    with open(path, "w") as fh:
        json.dump([asdict(r) for r in records], fh, indent=2)
    log.info("JSON written to %s", path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect hardware/software inventory from network devices via SSH."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("--host-file", help="File with one host per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    parser.add_argument("--format", choices=["csv", "json", "table"], default="table",
                        help="Output format (default: table)")
    parser.add_argument("-o", "--output", help="Output file path (stdout if omitted)")
    return parser


def print_table(records: List[DeviceRecord]) -> None:
    fmt = "{:<16} {:<20} {:<12} {:<18} {:<16} {:<10} {}"
    header = fmt.format("HOST", "HOSTNAME", "PLATFORM", "VERSION", "SERIAL", "MEM%", "UPTIME")
    print(header)
    print("-" * len(header))
    for r in records:
        status = f"{r.memory_used_pct}%" if not r.error else f"ERROR: {r.error}"
        print(fmt.format(r.host, r.hostname[:19], r.platform[:11],
                         r.software_version[:17], r.serial_number[:15],
                         status, r.uptime[:30]))


if __name__ == "__main__":
    import getpass

    parser = build_parser()
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    hosts: List[str] = []
    if args.device:
        hosts = [args.device]
    else:
        path = Path(args.host_file)
        if not path.exists():
            log.error("Host file not found: %s", args.host_file)
            sys.exit(1)
        hosts = [line.strip() for line in path.read_text().splitlines()
                 if line.strip() and not line.startswith("#")]

    records = [
        collect_inventory(h, args.username, password, port=args.port, timeout=args.timeout)
        for h in hosts
    ]

    output = args.output
    if args.format == "csv":
        dest = output or "inventory.csv"
        write_csv(records, dest)
    elif args.format == "json":
        dest = output or "inventory.json"
        write_json(records, dest)
    else:
        print_table(records)

    failed = sum(1 for r in records if r.error)
    if failed:
        log.warning("%d of %d device(s) had errors", failed, len(records))
        sys.exit(1)
```