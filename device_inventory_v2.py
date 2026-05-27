cdp_lldp_neighbors.py - Network neighbor discovery via CDP and LLDP protocols.

Purpose:
    Collects and parses CDP (Cisco Discovery Protocol) or LLDP (Link Layer
    Discovery Protocol) neighbor information from a network device via SSH.
    Useful for automated topology discovery, documentation, and change detection.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --protocol lldp
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --json
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --both

Prerequisites:
    pip install paramiko
    SSH access to target device with CDP or LLDP enabled on interfaces.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.debug("stderr: %s", err.strip())
    return output


def parse_cdp_neighbors(output):
    neighbors = []
    for entry in re.split(r"-{10,}", output):
        if not entry.strip():
            continue
        n = {}
        m = re.search(r"Device ID:\s*(.+)", entry)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"IP(?:v4)?\s+[Aa]ddress:\s*(\S+)", entry)
        if m:
            n["ip_address"] = m.group(1).strip()
        m = re.search(r"Platform:\s*(.+?),", entry)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Capabilities:\s*(.+)", entry)
        if m:
            n["capabilities"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+)", entry)
        if m:
            n["local_interface"] = m.group(1).rstrip(",")
        m = re.search(r"Port ID \(outgoing port\):\s*(.+)", entry)
        if m:
            n["remote_port"] = m.group(1).strip()
        m = re.search(r"Version\s*:\n?\s*(.+)", entry)
        if m:
            n["software_version"] = m.group(1).strip()
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    for entry in re.split(r"-{10,}", output):
        if not entry.strip():
            continue
        n = {}
        m = re.search(r"Local Intf:\s*(\S+)", entry)
        if m:
            n["local_interface"] = m.group(1).strip()
        m = re.search(r"Chassis id:\s*(.+)", entry)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"Port id:\s*(.+)", entry)
        if m:
            n["remote_port"] = m.group(1).strip()
        m = re.search(r"System Name:\s*(.+)", entry)
        if m:
            n["system_name"] = m.group(1).strip()
        m = re.search(r"System Description:\s*\n\s*(.+)", entry)
        if m:
            n["system_description"] = m.group(1).strip()
        m = re.search(r"IP:\s*(\S+)", entry)
        if m:
            n["ip_address"] = m.group(1).strip()
        m = re.search(r"System Capabilities:\s*(.+)", entry)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n.get("local_interface"):
            neighbors.append(n)
    return neighbors


def collect(client, protocol, timeout):
    commands = {"cdp": "show cdp neighbors detail", "lldp": "show lldp neighbors detail"}
    parsers = {"cdp": parse_cdp_neighbors, "lldp": parse_lldp_neighbors}

    cmd = commands[protocol]
    logger.debug("Running: %s", cmd)
    output = run_command(client, cmd, timeout)

    if "Invalid input" in output or "% Unknown command" in output:
        logger.warning("%s not supported on this device", protocol.upper())
        return []

    return parsers[protocol](output)


def print_table(neighbors, protocol):
    if not neighbors:
        print(f"  No {protocol.upper()} neighbors found.")
        return

    print(f"\n{'='*68}")
    print(f"  {protocol.upper()} Neighbors  ({len(neighbors)} found)")
    print(f"{'='*68}")
    for i, n in enumerate(neighbors, 1):
        label = n.get("device_id") or n.get("system_name", "Unknown")
        print(f"\n  [{i}] {label}")
        print(f"      Local Interface : {n.get('local_interface', 'N/A')}")
        print(f"      Remote Port     : {n.get('remote_port', 'N/A')}")
        print(f"      IP Address      : {n.get('ip_address', 'N/A')}")
        if protocol == "cdp":
            print(f"      Platform        : {n.get('platform', 'N/A')}")
            print(f"      Software        : {n.get('software_version', 'N/A')}")
        else:
            print(f"      System Name     : {n.get('system_name', 'N/A')}")
            print(f"      Description     : {n.get('system_description', 'N/A')}")
        print(f"      Capabilities    : {n.get('capabilities', 'N/A')}")
    print(f"\n{'='*68}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors from a network device via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp"],
        default="cdp",
        help="Discovery protocol to query (default: cdp)",
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Query both CDP and LLDP",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = ssh_connect(args.device, args.username, password, args.port, args.timeout)
    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Could not connect to {args.device}: {e}", file=sys.stderr)
        sys.exit(1)

    protocols = ["cdp", "lldp"] if args.both else [args.protocol]
    results = {}

    try:
        for proto in protocols:
            results[proto] = collect(client, proto, args.timeout)
    finally:
        client.close()

    if args.json_out:
        print(json.dumps({"device": args.device, "neighbors": results}, indent=2))
    else:
        for proto in protocols:
            print_table(results[proto], proto)


if __name__ == "__main__":
    main()