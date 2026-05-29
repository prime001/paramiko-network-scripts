```python
"""
neighbor_discovery.py - CDP/LLDP neighbor discovery and topology audit via SSH.

Purpose:
    Connects to a Cisco (or compatible) device over SSH using Paramiko, runs
    'show cdp neighbors detail' and/or 'show lldp neighbors detail', and parses
    the output into a structured neighbor inventory. Useful for ad-hoc topology
    audits and verifying cabling without access to a network controller.

Usage:
    python neighbor_discovery.py --host 192.168.1.1 --user admin --password secret
    python neighbor_discovery.py --host 192.168.1.1 --user admin --key ~/.ssh/id_rsa
    python neighbor_discovery.py --host 192.168.1.1 --user admin --password secret \
        --protocol lldp --output neighbors.json

Prerequisites:
    pip install paramiko
    CDP and/or LLDP must be enabled on the target device. The connecting user
    must have read access to 'show cdp/lldp neighbors detail'.
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

RECV_TIMEOUT = 5
RECV_BUFFER = 65535


def ssh_connect(host, port, username, password=None, key_path=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username, timeout=15)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def run_command(client, command, wait=RECV_TIMEOUT):
    shell = client.invoke_shell()
    shell.settimeout(wait)
    time.sleep(1)
    shell.recv(RECV_BUFFER)  # discard banner/prompt
    shell.send(command + "\n")
    time.sleep(wait)
    output = b""
    while shell.recv_ready():
        output += shell.recv(RECV_BUFFER)
    shell.close()
    return output.decode("utf-8", errors="replace")


def parse_cdp_neighbors(raw):
    neighbors = []
    blocks = re.split(r"-{10,}", raw)
    for block in blocks:
        if "Device ID" not in block:
            continue
        n = {}
        m = re.search(r"Device ID:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)", block)
        if m:
            n["local_interface"] = m.group(1)
            n["remote_interface"] = m.group(2)
        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n:
            neighbors.append(n)
    return neighbors


def parse_lldp_neighbors(raw):
    neighbors = []
    blocks = re.split(r"-{10,}|(?=Local Intf:)", raw)
    for block in blocks:
        if "System Name" not in block and "Port Description" not in block:
            continue
        n = {}
        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"Management Addresses.*?IP:\s*(\S+)", block, re.DOTALL)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"System Description:\s*\n\s*(.+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            n["local_interface"] = m.group(1)
        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            n["remote_interface"] = m.group(1)
        m = re.search(r"System Capabilities:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n:
            neighbors.append(n)
    return neighbors


def print_neighbors(neighbors, protocol):
    if not neighbors:
        print(f"No {protocol.upper()} neighbors found.")
        return
    print(f"\n{'=' * 70}")
    print(f"  {protocol.upper()} Neighbors ({len(neighbors)} found)")
    print(f"{'=' * 70}")
    for n in neighbors:
        print(f"  Device:        {n.get('device_id', 'N/A')}")
        print(f"  IP Address:    {n.get('ip_address', 'N/A')}")
        print(f"  Platform:      {n.get('platform', 'N/A')}")
        print(f"  Local Iface:   {n.get('local_interface', 'N/A')}")
        print(f"  Remote Iface:  {n.get('remote_interface', 'N/A')}")
        print(f"  Capabilities:  {n.get('capabilities', 'N/A')}")
        print(f"  {'-' * 66}")


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors on a network device via SSH."
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", help="Path to SSH private key file")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp", "both"],
        default="both",
        help="Discovery protocol to query (default: both)",
    )
    parser.add_argument("--output", help="Write JSON results to this file path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if not args.password and not args.key:
        args.password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    results = {}

    try:
        logger.info("Connecting to %s:%d", args.host, args.port)
        client = ssh_connect(args.host, args.port, args.user, args.password, args.key)
        logger.info("Connected")

        if args.protocol in ("cdp", "both"):
            logger.info("Querying CDP neighbors")
            raw = run_command(client, "show cdp neighbors detail")
            neighbors = parse_cdp_neighbors(raw)
            results["cdp"] = neighbors
            print_neighbors(neighbors, "cdp")

        if args.protocol in ("lldp", "both"):
            logger.info("Querying LLDP neighbors")
            raw = run_command(client, "show lldp neighbors detail")
            neighbors = parse_lldp_neighbors(raw)
            results["lldp"] = neighbors
            print_neighbors(neighbors, "lldp")

        client.close()

    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        logger.error("SSH error: %s", exc)
        sys.exit(1)
    except OSError as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                json.dump(results, fh, indent=2)
            logger.info("Results written to %s", args.output)
        except OSError as exc:
            logger.error("Failed to write output file: %s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()
```