```python
"""
cdp_lldp_neighbors.py - Collect CDP/LLDP neighbor topology from network devices.

Purpose:
    Connects to a Cisco (or compatible) network device via SSH and retrieves
    neighbor adjacency data using CDP or LLDP. Useful for building layer-2/3
    topology maps, auditing physical connectivity, and verifying cabling.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --protocol lldp --format json
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa -v

Prerequisites:
    pip install paramiko
    CDP or LLDP must be enabled on the target device.
    SSH access with privilege level sufficient to run 'show' commands.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        connect_kwargs["key_filename"] = key_file
        connect_kwargs["look_for_keys"] = True
    elif password:
        connect_kwargs["password"] = password
    try:
        client.connect(**connect_kwargs)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except Exception as exc:
        log.error("Connection to %s failed: %s", host, exc)
        raise
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr from device: %s", err)
    return output


def parse_cdp_neighbors(raw):
    neighbors = []
    blocks = re.split(r"(?=Device ID:)", raw)
    for block in blocks:
        if "Device ID:" not in block:
            continue
        entry = {}
        m = re.search(r"Device ID:\s*(.+)", block)
        if m:
            entry["device_id"] = m.group(1).strip()
        m = re.search(r"IP address:\s*(\S+)", block)
        entry["ip"] = m.group(1) if m else ""
        m = re.search(r"Platform:\s*([^,]+)", block)
        entry["platform"] = m.group(1).strip() if m else ""
        m = re.search(r"Interface:\s*(\S+)", block)
        entry["local_port"] = m.group(1).rstrip(",") if m else ""
        m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)
        entry["remote_port"] = m.group(1) if m else ""
        m = re.search(r"Duplex:\s*(\S+)", block)
        entry["duplex"] = m.group(1) if m else ""
        if entry.get("device_id"):
            neighbors.append(entry)
    return neighbors


def parse_lldp_neighbors(raw):
    neighbors = []
    blocks = re.split(r"(?=Local Intf:)", raw)
    for block in blocks:
        if "Local Intf:" not in block:
            continue
        entry = {}
        m = re.search(r"Local Intf:\s*(\S+)", block)
        entry["local_port"] = m.group(1) if m else ""
        m = re.search(r"System Name:\s*(.+)", block)
        entry["device_id"] = m.group(1).strip() if m else ""
        m = re.search(r"Port id:\s*(\S+)", block)
        entry["remote_port"] = m.group(1) if m else ""
        m = re.search(r"Management Addresses[:\s]+(\S+)", block)
        entry["ip"] = m.group(1) if m else ""
        m = re.search(r"System Description[:\s]+(.+)", block)
        entry["platform"] = m.group(1).strip() if m else ""
        entry["duplex"] = ""
        if entry.get("device_id") or entry.get("local_port"):
            neighbors.append(entry)
    return neighbors


def print_table(neighbors, host, protocol):
    print(f"\n{protocol.upper()} neighbors on {host} ({len(neighbors)} found):")
    header = f"{'Device ID':<32} {'Local Port':<18} {'Remote Port':<18} {'IP':<16} Platform"
    print(header)
    print("-" * len(header) + "-" * 10)
    for n in neighbors:
        print(
            f"{n['device_id']:<32} {n['local_port']:<18} {n['remote_port']:<18}"
            f" {n['ip']:<16} {n['platform']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Collect CDP/LLDP neighbor topology from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("-k", "--key-file", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp"],
        default="cdp",
        help="Neighbor discovery protocol (default: cdp)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.key_file and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        log.info("Connecting to %s", args.device)
        client = ssh_connect(args.device, args.username, args.password, args.key_file, args.port)
    except Exception:
        sys.exit(1)

    try:
        command = f"show {args.protocol} neighbors detail"
        log.info("Running: %s", command)
        raw = run_command(client, command)
    finally:
        client.close()

    neighbors = parse_cdp_neighbors(raw) if args.protocol == "cdp" else parse_lldp_neighbors(raw)

    if not neighbors:
        log.warning(
            "No neighbors found — verify %s is enabled on %s",
            args.protocol.upper(),
            args.device,
        )
        sys.exit(0)

    if args.format == "json":
        print(json.dumps(
            {"device": args.device, "protocol": args.protocol, "neighbors": neighbors},
            indent=2,
        ))
    else:
        print_table(neighbors, args.device, args.protocol)


if __name__ == "__main__":
    main()
```