```python
"""
cdp_lldp_neighbors.py - CDP/LLDP Neighbor Discovery and Topology Mapper

Connects to a Cisco IOS/NX-OS device via SSH and collects neighbor information
from CDP (Cisco Discovery Protocol) or LLDP (Link Layer Discovery Protocol).
Parses structured neighbor data useful for topology documentation and audits.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --protocol lldp --json
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --output neighbors.json

Prerequisites:
    pip install paramiko
    CDP or LLDP must be enabled on the target device.
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
    entries = re.split(r"-{10,}", output)

    for entry in entries:
        if not entry.strip():
            continue

        neighbor = {}

        m = re.search(r"Device ID:\s*(.+)", entry)
        if not m:
            continue
        neighbor["device_id"] = m.group(1).strip()

        m = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\S+)", entry)
        if m:
            neighbor["ip_address"] = m.group(1)

        m = re.search(r"Platform:\s*([^,]+)", entry)
        if m:
            neighbor["platform"] = m.group(1).strip()

        m = re.search(r"Capabilities:\s*(.+)", entry)
        if m:
            neighbor["capabilities"] = m.group(1).strip()

        m = re.search(r"Interface:\s*(\S+),\s*Port ID", entry)
        if m:
            neighbor["local_interface"] = m.group(1)

        m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", entry)
        if m:
            neighbor["remote_port"] = m.group(1)

        m = re.search(r"Holdtime\s*:\s*(\d+)", entry)
        if m:
            neighbor["holdtime_sec"] = int(m.group(1))

        m = re.search(r"Version :\s*\n\s*(.+)", entry)
        if m:
            neighbor["software_version"] = m.group(1).strip()

        neighbors.append(neighbor)

    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    entries = re.split(r"-{10,}", output)

    for entry in entries:
        if not entry.strip():
            continue

        neighbor = {}

        m = re.search(r"System Name:\s*(.+)", entry)
        if m:
            neighbor["device_id"] = m.group(1).strip()

        m = re.search(r"Management Addresses:\s*\n\s+IP:\s*(\S+)", entry)
        if not m:
            m = re.search(r"Management Address:\s*(\S+)", entry)
        if m:
            neighbor["ip_address"] = m.group(1)

        m = re.search(r"System Description:\s*\n\s*(.+)", entry)
        if m:
            neighbor["platform"] = m.group(1).strip()

        m = re.search(r"System Capabilities:\s*(.+)", entry)
        if m:
            neighbor["capabilities"] = m.group(1).strip()

        m = re.search(r"Local Intf:\s*(\S+)", entry)
        if m:
            neighbor["local_interface"] = m.group(1)

        m = re.search(r"Port id:\s*(\S+)", entry)
        if m:
            neighbor["remote_port"] = m.group(1)

        if neighbor.get("device_id") or neighbor.get("local_interface"):
            neighbors.append(neighbor)

    return neighbors


def print_table(neighbors, protocol):
    if not neighbors:
        print(f"No {protocol.upper()} neighbors found.")
        return

    print(f"\n{'='*80}")
    print(f"  {protocol.upper()} Neighbors  ({len(neighbors)} found)")
    print(f"{'='*80}")
    print(
        f"{'Device ID':<30} {'Local Intf':<18} {'Remote Port':<18} {'IP Address':<16}"
    )
    print(f"{'-'*30} {'-'*18} {'-'*18} {'-'*16}")

    for n in neighbors:
        print(
            f"{n.get('device_id', 'N/A'):<30} "
            f"{n.get('local_interface', 'N/A'):<18} "
            f"{n.get('remote_port', 'N/A'):<18} "
            f"{n.get('ip_address', 'N/A'):<16}"
        )

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors on a Cisco device via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp"],
        default="cdp",
        help="Discovery protocol (default: cdp)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print output as JSON",
    )
    parser.add_argument("--output", metavar="FILE", help="Write JSON results to file")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    try:
        logger.info("Connecting to %s:%d", args.device, args.port)
        client = ssh_connect(args.device, args.username, password, args.port)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        command = (
            "show cdp neighbors detail"
            if args.protocol == "cdp"
            else "show lldp neighbors detail"
        )
        logger.info("Running: %s", command)
        raw_output = run_command(client, command)
    finally:
        client.close()

    if args.protocol == "cdp":
        neighbors = parse_cdp_neighbors(raw_output)
    else:
        neighbors = parse_lldp_neighbors(raw_output)

    result = {
        "device": args.device,
        "protocol": args.protocol.upper(),
        "neighbor_count": len(neighbors),
        "neighbors": neighbors,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        logger.info("Results written to %s", args.output)

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        print_table(neighbors, args.protocol)


if __name__ == "__main__":
    main()