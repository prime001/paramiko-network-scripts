```python
"""
interface_error_monitor.py — Interface Error Counter Monitor via SSH

Purpose:
    Connects to a Cisco IOS/IOS-XE device over SSH and retrieves per-interface
    error counters (input errors, output errors, CRC, resets, ignored). Flags
    interfaces whose error counts exceed configurable thresholds and optionally
    exports results to CSV or JSON.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 192.168.1.1 -u admin --ask-pass \
        --threshold 100 --format json --output errors.json
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \
        --interface GigabitEthernet0/1

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    User account requires at minimum 'show' privilege (level 1).
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

RECV_TIMEOUT = 10
RECV_BUFFER = 65535


@dataclass
class InterfaceErrors:
    name: str
    input_errors: int = 0
    output_errors: int = 0
    crc: int = 0
    resets: int = 0
    ignored: int = 0
    overrun: int = 0
    flagged: bool = field(default=False, repr=False)


def _recv_until_prompt(shell: paramiko.Channel, timeout: int = RECV_TIMEOUT) -> str:
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(RECV_BUFFER).decode("utf-8", errors="replace")
            output += chunk
            if re.search(r"[>#]\s*$", output.splitlines()[-1] if output.splitlines() else ""):
                break
        else:
            time.sleep(0.15)
    return output


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info("Connecting to %s:%d as %s", host, port, username)
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


def run_command(shell: paramiko.Channel, command: str) -> str:
    shell.send(command + "\n")
    return _recv_until_prompt(shell)


def parse_error_blocks(raw: str) -> List[InterfaceErrors]:
    """Parse 'show interfaces' output into InterfaceErrors objects."""
    results: List[InterfaceErrors] = []

    # Split on interface header lines, e.g. "GigabitEthernet0/0 is up, ..."
    blocks = re.split(r"(?=^\S+\s+is\s+(?:up|down|administratively down))", raw, flags=re.MULTILINE)

    for block in blocks:
        if not block.strip():
            continue
        name_match = re.match(r"^(\S+)\s+is\s+", block)
        if not name_match:
            continue
        iface = InterfaceErrors(name=name_match.group(1))

        def _extract(pattern: str, text: str, default: int = 0) -> int:
            m = re.search(pattern, text)
            return int(m.group(1).replace(",", "")) if m else default

        iface.input_errors = _extract(r"(\d[\d,]*)\s+input errors", block)
        iface.output_errors = _extract(r"(\d[\d,]*)\s+output errors", block)
        iface.crc = _extract(r"(\d[\d,]*)\s+CRC", block)
        iface.resets = _extract(r"(\d[\d,]*)\s+(?:interface resets|resets)", block)
        iface.ignored = _extract(r"(\d[\d,]*)\s+ignored", block)
        iface.overrun = _extract(r"(\d[\d,]*)\s+overrun", block)
        results.append(iface)

    return results


def apply_threshold(interfaces: List[InterfaceErrors], threshold: int) -> List[InterfaceErrors]:
    for iface in interfaces:
        total = iface.input_errors + iface.output_errors + iface.crc
        iface.flagged = total >= threshold
    return interfaces


def print_table(interfaces: List[InterfaceErrors]) -> None:
    header = f"{'Interface':<35} {'InErr':>8} {'OutErr':>8} {'CRC':>8} {'Resets':>8} {'Flag'}"
    print(header)
    print("-" * len(header))
    for i in interfaces:
        flag = "*** ALERT ***" if i.flagged else ""
        print(f"{i.name:<35} {i.input_errors:>8,} {i.output_errors:>8,} {i.crc:>8,} {i.resets:>8,}  {flag}")


def export(interfaces: List[InterfaceErrors], fmt: str, path: str) -> None:
    data = [asdict(i) for i in interfaces]
    if fmt == "json":
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
    elif fmt == "csv":
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
    log.info("Results written to %s (%s)", path, fmt)


def main(args: argparse.Namespace) -> int:
    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        client = connect(args.host, args.port, args.username, password)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    try:
        shell = client.invoke_shell(width=250, height=200)
        _recv_until_prompt(shell)
        run_command(shell, "terminal length 0")

        cmd = f"show interfaces {args.interface}" if args.interface else "show interfaces"
        log.info("Running: %s", cmd)
        raw = run_command(shell, cmd)
    finally:
        client.close()

    interfaces = parse_error_blocks(raw)
    if not interfaces:
        log.warning("No interface data parsed — verify credentials and device output.")
        return 2

    interfaces = apply_threshold(interfaces, args.threshold)
    print_table(interfaces)

    flagged = [i for i in interfaces if i.flagged]
    if flagged:
        log.warning("%d interface(s) exceeded error threshold of %d", len(flagged), args.threshold)

    if args.output and args.format:
        export(interfaces, args.format, args.output)

    return 1 if flagged else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Monitor interface error counters on Cisco IOS/IOS-XE devices."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--ask-pass", dest="password", action="store_const", const=None,
                        help="Force interactive password prompt")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--interface", default="", metavar="INTF",
                        help="Limit to a single interface (e.g. GigabitEthernet0/1)")
    parser.add_argument("--threshold", type=int, default=0,
                        help="Flag interfaces with (input+output+CRC) errors >= this value (default: 0 = off)")
    parser.add_argument("--format", choices=["json", "csv"], default=None,
                        help="Export format for results")
    parser.add_argument("--output", default=None, metavar="FILE",
                        help="Output file path for export (requires --format)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    parsed = parser.parse_args()

    if parsed.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if bool(parsed.output) != bool(parsed.format):
        parser.error("--output and --format must be used together.")

    sys.exit(main(parsed))
```