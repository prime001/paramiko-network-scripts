```python
#!/usr/bin/env python3
"""
interface_errors.py - Network Interface Error Counter Monitor

Connects to a Cisco IOS/IOS-XE device via SSH and polls interface error
counters to surface problematic interfaces. Reports CRC errors, input
errors, input/output drops, and interface resets that exceed a configurable
threshold. Useful for catching degrading links before they cause outages.

Prerequisites:
    pip install paramiko

Usage:
    python interface_errors.py -d 192.168.1.1 -u admin -p secret
    python interface_errors.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python interface_errors.py -d 192.168.1.1 -u admin -p secret --threshold 10
    python interface_errors.py -d 192.168.1.1 -u admin -p secret --all --json
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
logger = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_file),
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Either --password or --key must be provided")

    try:
        client.connect(**kwargs)
        return client
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        raise
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection to %s failed: %s", host, exc)
        raise


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.debug("Device stderr: %s", err.strip())
    return out


def parse_interface_errors(output):
    """Parse 'show interfaces' into a list of per-interface counter dicts."""
    interfaces = []
    current = None

    for line in output.splitlines():
        m = re.match(
            r'^(\S+)\s+is\s+(administratively down|up|down).*line protocol is\s+(up|down)',
            line,
        )
        if m:
            if current:
                interfaces.append(current)
            current = {
                "name": m.group(1),
                "admin_status": "admin-down" if "administratively" in line else m.group(2),
                "proto_status": m.group(3),
                "input_errors": 0,
                "crc": 0,
                "input_drops": 0,
                "output_drops": 0,
                "output_errors": 0,
                "resets": 0,
            }
            continue

        if current is None:
            continue

        m = re.search(r'(\d+)\s+input errors,\s+(\d+)\s+CRC', line)
        if m:
            current["input_errors"] = int(m.group(1))
            current["crc"] = int(m.group(2))

        m = re.search(r'Input queue:\s+\d+/\d+/(\d+)/', line)
        if m:
            current["input_drops"] = int(m.group(1))

        m = re.search(r'Total output drops:\s+(\d+)', line)
        if m:
            current["output_drops"] = int(m.group(1))

        m = re.search(r'(\d+)\s+output errors.*?(\d+)\s+interface resets', line)
        if m:
            current["output_errors"] = int(m.group(1))
            current["resets"] = int(m.group(2))

    if current:
        interfaces.append(current)

    return interfaces


def filter_by_threshold(interfaces, threshold):
    counter_fields = ("input_errors", "crc", "input_drops", "output_drops", "output_errors", "resets")
    return [i for i in interfaces if any(i.get(f, 0) > threshold for f in counter_fields)]


def print_table(interfaces, device):
    col = "{:<36} {:<12} {:>9} {:>9} {:>9} {:>9} {:>9}"
    header = col.format("Interface", "Status", "InErr", "CRC", "InDrop", "OutDrop", "Resets")
    print(f"\nInterface Error Report: {device}\n")
    print(header)
    print("-" * len(header))
    for i in interfaces:
        status = f"{i['admin_status']}/{i['proto_status']}"
        print(col.format(
            i["name"], status,
            i["input_errors"], i["crc"],
            i["input_drops"], i["output_drops"],
            i["resets"],
        ))


def build_parser():
    p = argparse.ArgumentParser(
        description="Report interface error counters from a Cisco IOS/IOS-XE device"
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--key", dest="key_file", metavar="PATH", help="SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--threshold", type=int, default=0,
        help="Minimum counter value to flag an interface (default: 0)",
    )
    p.add_argument("--all", dest="show_all", action="store_true",
                   help="Show all interfaces, not just those with errors")
    p.add_argument("--json", dest="json_out", action="store_true", help="Output as JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.key_file and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = ssh_connect(
            args.device, args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = run_command(client, "show interfaces")
    finally:
        client.close()

    interfaces = parse_interface_errors(raw)
    if not interfaces:
        print("No interfaces parsed — verify device output format.", file=sys.stderr)
        sys.exit(1)

    display = interfaces if args.show_all else filter_by_threshold(interfaces, args.threshold)

    if args.json_out:
        print(json.dumps(display, indent=2))
    elif not display:
        qualifier = "all" if args.show_all else f"above threshold {args.threshold}"
        print(f"No interfaces with errors ({qualifier}) on {args.device}.")
    else:
        print_table(display, args.device)
        print(f"\n{len(display)} of {len(interfaces)} interfaces reported.")
```