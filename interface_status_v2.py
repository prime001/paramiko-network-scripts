```python
"""
Interface Error Monitor - SSH-based interface error counter analysis for Cisco IOS/IOS-XE.

Purpose:
    Connects to a network device via SSH, retrieves interface statistics, and reports
    interfaces whose error counters exceed configurable thresholds. Useful for catching
    degraded links (flapping, CRC storms, input drops) before they cause outages.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \\
        --crc-errors 10 --flaps 5 --skip-down --output json

Prerequisites:
    pip install paramiko
    SSH access to target device with privilege to run 'show interfaces'.
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import List, Optional

import paramiko

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    status: str = "unknown"
    input_errors: int = 0
    crc_errors: int = 0
    output_errors: int = 0
    input_drops: int = 0
    output_drops: int = 0
    resets: int = 0
    alerts: List[str] = field(default_factory=list)


def ssh_connect(host: str, username: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=username, password=password,
        timeout=15, look_for_keys=False, allow_agent=False,
    )
    return client


def run_command(client: paramiko.SSHClient, command: str) -> str:
    transport = client.get_transport()
    channel = transport.open_session()
    channel.settimeout(30)
    channel.exec_command(command)
    output = b""
    while True:
        if channel.recv_ready():
            chunk = channel.recv(4096)
            if not chunk:
                break
            output += chunk
        elif channel.exit_status_ready():
            while channel.recv_ready():
                output += channel.recv(4096)
            break
    channel.close()
    return output.decode("utf-8", errors="replace")


def parse_interfaces(raw: str) -> List[InterfaceErrors]:
    interfaces: List[InterfaceErrors] = []
    current: Optional[InterfaceErrors] = None

    for line in raw.splitlines():
        m = re.match(
            r'^(\S+(?:Ethernet|Serial|Tunnel|Loopback|Vlan|Port-channel)\S*)\s+is\s+(\S+)',
            line, re.IGNORECASE,
        )
        if m:
            if current:
                interfaces.append(current)
            current = InterfaceErrors(name=m.group(1), status=m.group(2).lower())
            continue

        if current is None:
            continue

        m = re.search(r'(\d+) input errors?,\s*(\d+) CRC', line)
        if m:
            current.input_errors = int(m.group(1))
            current.crc_errors = int(m.group(2))
            continue

        m = re.search(r'(\d+) output errors?', line)
        if m:
            current.output_errors = int(m.group(1))
            continue

        m = re.search(r'(\d+) input drops?', line)
        if m:
            current.input_drops = int(m.group(1))
            continue

        m = re.search(r'(\d+) output drops?', line)
        if m:
            current.output_drops = int(m.group(1))
            continue

        m = re.search(r'(\d+) interface resets?', line)
        if m:
            current.resets = int(m.group(1))
            continue

    if current:
        interfaces.append(current)
    return interfaces


def apply_thresholds(interfaces, args) -> List[InterfaceErrors]:
    checks = [
        ("input_errors", args.input_errors, "input errors"),
        ("crc_errors", args.crc_errors, "CRC errors"),
        ("output_errors", args.output_errors, "output errors"),
        ("input_drops", args.input_drops, "input drops"),
        ("output_drops", args.output_drops, "output drops"),
        ("resets", args.resets, "interface resets"),
    ]
    flagged = []
    for iface in interfaces:
        if args.skip_down and iface.status != "up":
            continue
        for attr, threshold, label in checks:
            val = getattr(iface, attr)
            if val >= threshold:
                iface.alerts.append(f"{label}={val} (threshold {threshold})")
        if iface.alerts:
            flagged.append(iface)
    return flagged


def print_table(flagged: List[InterfaceErrors], total: int) -> None:
    print(f"\nScanned {total} interfaces — {len(flagged)} exceeded thresholds.\n")
    if not flagged:
        print("No interfaces exceeded configured thresholds.")
        return
    hdr = f"{'Interface':<32} {'Status':<10} {'In-Err':>8} {'CRC':>8} {'Out-Err':>8} {'Resets':>8}  Alerts"
    print(hdr)
    print("-" * len(hdr))
    for i in flagged:
        print(
            f"{i.name:<32} {i.status:<10} {i.input_errors:>8} {i.crc_errors:>8} "
            f"{i.output_errors:>8} {i.resets:>8}  {'; '.join(i.alerts)}"
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Report interface error counters exceeding thresholds.")
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--input-errors", type=int, default=100, metavar="N")
    p.add_argument("--crc-errors", type=int, default=50, metavar="N")
    p.add_argument("--output-errors", type=int, default=100, metavar="N")
    p.add_argument("--input-drops", type=int, default=500, metavar="N")
    p.add_argument("--output-drops", type=int, default=500, metavar="N")
    p.add_argument("--resets", type=int, default=10, metavar="N", help="Interface reset threshold")
    p.add_argument("--skip-down", action="store_true", help="Ignore down interfaces")
    p.add_argument("--output", choices=["table", "json"], default="table")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = ssh_connect(args.device, args.username, password, args.port)
    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: Cannot connect to {args.device}: {exc}", file=sys.stderr)
        return 1

    try:
        raw = run_command(client, "show interfaces")
    except Exception as exc:
        print(f"ERROR: Command failed: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

    all_interfaces = parse_interfaces(raw)
    if not all_interfaces:
        print("WARNING: No interfaces parsed — check device output.", file=sys.stderr)
        return 2

    flagged = apply_thresholds(all_interfaces, args)

    if args.output == "json":
        result = {
            "device": args.device,
            "total_interfaces": len(all_interfaces),
            "flagged_count": len(flagged),
            "flagged": [asdict(i) for i in flagged],
        }
        print(json.dumps(result, indent=2))
    else:
        print_table(flagged, len(all_interfaces))

    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
```