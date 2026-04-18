```python
#!/usr/bin/env python3
"""
lldp_neighbor_map.py - LLDP/CDP Neighbor Discovery via SSH

Connects to a network device over SSH using Paramiko, collects LLDP and/or
CDP neighbor entries, and outputs a structured neighbor table. Useful for
building ad-hoc topology snapshots without a full NMS deployment.

Usage:
    python lldp_neighbor_map.py -d 192.168.1.1 -u admin -p secret
    python lldp_neighbor_map.py -d 10.0.0.1 -u admin --key ~/.ssh/id_rsa --protocol cdp
    python lldp_neighbor_map.py -d 10.0.0.1 -u admin -p secret --json

Prerequisites:
    pip install paramiko
    Target device must have LLDP or CDP enabled and the SSH user needs
    at least read-only (show) privilege level.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.WARNING)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_path=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    elif password:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr for %r: %s", command, err)
    return output


def parse_lldp_neighbors(raw):
    """Parse 'show lldp neighbors detail' output (IOS/IOS-XE style)."""
    neighbors = []
    blocks = re.split(r"-{10,}", raw)
    for block in blocks:
        if not block.strip():
            continue
        entry = {}
        m = re.search(r"System Name:\s+(.+)", block)
        if m:
            entry["system_name"] = m.group(1).strip()
        m = re.search(r"Port ID:\s+(.+)", block)
        if m:
            entry["remote_port"] = m.group(1).strip()
        m = re.search(r"Local Intf:\s+(.+)", block)
        if m:
            entry["local_port"] = m.group(1).strip()
        m = re.search(r"System Description:\s*\n\s*(.+)", block)
        if m:
            entry["platform"] = m.group(1).strip()
        m = re.search(r"Management Addresses[^\n]*\n\s+([\d.]+)", block)
        if m:
            entry["mgmt_ip"] = m.group(1).strip()
        if entry.get("system_name") or entry.get("remote_port"):
            neighbors.append(entry)
    return neighbors


def parse_cdp_neighbors(raw):
    """Parse 'show cdp neighbors detail' output (IOS/IOS-XE style)."""
    neighbors = []
    blocks = re.split(r"-{5,}", raw)
    for block in blocks:
        if not block.strip():
            continue
        entry = {}
        m = re.search(r"Device ID:\s+(.+)", block)
        if m:
            entry["system_name"] = m.group(1).strip()
        m = re.search(r"Interface:\s+([^,]+),\s+Port ID[^:]*:\s+(.+)", block)
        if m:
            entry["local_port"] = m.group(1).strip()
            entry["remote_port"] = m.group(2).strip()
        m = re.search(r"Platform:\s+([^,]+)", block)
        if m:
            entry["platform"] = m.group(1).strip()
        m = re.search(r"IP(?:v4)? [Aa]ddress:\s+([\d.]+)", block)
        if m:
            entry["mgmt_ip"] = m.group(1).strip()
        if entry.get("system_name"):
            neighbors.append(entry)
    return neighbors


def collect_neighbors(client, protocol):
    neighbors = []
    if protocol in ("lldp", "both"):
        log.info("Collecting LLDP neighbors")
        raw = run_command(client, "show lldp neighbors detail")
        parsed = parse_lldp_neighbors(raw)
        for n in parsed:
            n["protocol"] = "LLDP"
        neighbors.extend(parsed)
    if protocol in ("cdp", "both"):
        log.info("Collecting CDP neighbors")
        raw = run_command(client, "show cdp neighbors detail")
        parsed = parse_cdp_neighbors(raw)
        for n in parsed:
            n["protocol"] = "CDP"
        neighbors.extend(parsed)
    return neighbors


def print_table(neighbors):
    if not neighbors:
        print("No neighbors found.")
        return
    col_w = {"proto": 6, "local": 18, "remote_name": 28, "remote_port": 20, "mgmt": 16}
    header = (
        f"{'Proto':<{col_w['proto']}}  "
        f"{'Local Port':<{col_w['local']}}  "
        f"{'Neighbor':<{col_w['remote_name']}}  "
        f"{'Remote Port':<{col_w['remote_port']}}  "
        f"{'Mgmt IP':<{col_w['mgmt']}}"
    )
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for n in neighbors:
        print(
            f"{n.get('protocol','?'):<{col_w['proto']}}  "
            f"{n.get('local_port','?'):<{col_w['local']}}  "
            f"{n.get('system_name','?'):<{col_w['remote_name']}}  "
            f"{n.get('remote_port','?'):<{col_w['remote_port']}}  "
            f"{n.get('mgmt_ip','N/A'):<{col_w['mgmt']}}"
        )
    print(sep)
    print(f"Total neighbors: {len(neighbors)}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Collect LLDP/CDP neighbor information from a network device via SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", metavar="KEY_FILE", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol",
        choices=["lldp", "cdp", "both"],
        default="both",
        help="Discovery protocol to query (default: both)",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of table")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        log.info("Connecting to %s:%d", args.device, args.port)
        client = ssh_connect(
            host=args.device,
            username=args.username,
            password=password,
            key_path=args.key,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        print(f"ERROR: Could not connect to {args.device}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        neighbors = collect_neighbors(client, args.protocol)
    except Exception as exc:
        print(f"ERROR: Failed to collect neighbors: {exc}", file=sys.stderr)
        client.close()
        sys.exit(1)
    finally:
        client.close()

    if args.json:
        print(json.dumps(neighbors, indent=2))
    else:
        print(f"\nNeighbor table for {args.device}  (protocol={args.protocol})\n")
        print_table(neighbors)
```