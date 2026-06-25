#!/usr/bin/env python3
"""
CDP/LLDP Neighbor Discovery Parser

Connects to a network device via SSH, retrieves CDP and/or LLDP neighbor
tables, and presents a structured view of directly connected peers. Useful
for automated topology mapping, network documentation, and change validation.

Usage:
    python neighbor_discovery.py -d 192.168.1.1 -u admin -p secret
    python neighbor_discovery.py -d 192.168.1.1 -u admin --protocol lldp
    python neighbor_discovery.py -d 192.168.1.1 -u admin --protocol both --json
    python neighbor_discovery.py -d 192.168.1.1 -u admin --output topology.json

Prerequisites:
    pip install paramiko
    SSH access to target device with CDP and/or LLDP enabled
    Tested against Cisco IOS/IOS-XE (CDP) and IEEE 802.1AB LLDP implementations
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from typing import List

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class Neighbor:
    device_id: str
    local_port: str
    remote_port: str
    platform: str = ""
    ip_address: str = ""
    capabilities: str = ""
    software_version: str = ""
    protocol: str = ""


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )
        logger.info("Connected to %s:%d", host, port)
        return client
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except paramiko.SSHException as e:
        logger.error("SSH error connecting to %s: %s", host, e)
        sys.exit(1)
    except OSError as e:
        logger.error("Connection failed to %s: %s", host, e)
        sys.exit(1)


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        if error and "warning" not in error.lower():
            logger.warning("Stderr from '%s': %s", command, error.strip())
        return output
    except paramiko.SSHException as e:
        logger.error("Failed to execute '%s': %s", command, e)
        return ""


def parse_cdp_neighbors(output: str) -> List[Neighbor]:
    neighbors = []
    blocks = re.split(r"-{10,}", output)

    for block in blocks:
        if not block.strip():
            continue
        device_id_match = re.search(r"Device ID:\s*(.+)", block)
        if not device_id_match:
            continue

        neighbor = Neighbor(
            device_id=device_id_match.group(1).strip(),
            local_port="",
            remote_port="",
            protocol="cdp",
        )

        m = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\S+)", block)
        if m:
            neighbor.ip_address = m.group(1)

        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            neighbor.platform = m.group(1).strip()

        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            neighbor.capabilities = m.group(1).strip()

        m = re.search(r"Interface:\s*(\S+)", block)
        if m:
            neighbor.local_port = m.group(1).rstrip(",")

        m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)
        if m:
            neighbor.remote_port = m.group(1)

        m = re.search(r"Version\s*:\s*\n\s*(.+)", block)
        if m:
            neighbor.software_version = m.group(1).strip()

        neighbors.append(neighbor)

    return neighbors


def parse_lldp_neighbors(output: str) -> List[Neighbor]:
    neighbors = []
    blocks = re.split(r"(?=Local Intf:)", output)

    for block in blocks:
        if not block.strip():
            continue
        local_match = re.search(r"Local Intf:\s*(\S+)", block)
        if not local_match:
            continue

        neighbor = Neighbor(
            device_id="",
            local_port=local_match.group(1).strip(),
            remote_port="",
            protocol="lldp",
        )

        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            neighbor.device_id = m.group(1).strip()
        else:
            m = re.search(r"Chassis id:\s*(.+)", block)
            if m:
                neighbor.device_id = m.group(1).strip()

        m = re.search(r"IP:\s*(\S+)", block)
        if not m:
            m = re.search(r"Management Addresses:\s*\n\s*(\S+)", block)
        if m:
            neighbor.ip_address = m.group(1).strip()

        m = re.search(r"Port id:\s*(.+)", block)
        if m:
            neighbor.remote_port = m.group(1).strip()

        m = re.search(r"System Capabilities:\s*(.+)", block)
        if m:
            neighbor.capabilities = m.group(1).strip()

        if neighbor.device_id or neighbor.ip_address:
            neighbors.append(neighbor)

    return neighbors


def print_table(neighbors: List[Neighbor], device: str) -> None:
    if not neighbors:
        print(f"No neighbors discovered on {device}.")
        return

    col = (30, 18, 18, 16, 20, 5)
    header = (
        f"{'Device ID':<{col[0]}} {'Local Port':<{col[1]}} {'Remote Port':<{col[2]}} "
        f"{'IP Address':<{col[3]}} {'Platform':<{col[4]}} {'Proto':<{col[5]}}"
    )
    print(f"\nNeighbors on {device}:")
    print(header)
    print("-" * sum(col))
    for n in neighbors:
        print(
            f"{n.device_id[:col[0]-1]:<{col[0]}} {n.local_port[:col[1]-1]:<{col[1]}} "
            f"{n.remote_port[:col[2]-1]:<{col[2]}} {n.ip_address[:col[3]-1]:<{col[3]}} "
            f"{n.platform[:col[4]-1]:<{col[4]}} {n.protocol:<{col[5]}}"
        )
    print(f"\nTotal: {len(neighbors)} neighbor(s)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover and parse CDP/LLDP neighbors from a network device via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP address")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp", "both"],
        default="cdp",
        help="Discovery protocol to query (default: cdp)",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--output", metavar="FILE", help="Write JSON results to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    client = ssh_connect(args.device, args.username, password, args.port)

    try:
        neighbors: List[Neighbor] = []

        if args.protocol in ("cdp", "both"):
            logger.debug("Fetching CDP neighbor details")
            out = run_command(client, "show cdp neighbors detail")
            if out and "CDP is not enabled" not in out and "Invalid input" not in out:
                found = parse_cdp_neighbors(out)
                logger.info("CDP: %d neighbor(s)", len(found))
                neighbors.extend(found)
            else:
                logger.warning("CDP unavailable or not enabled on %s", args.device)

        if args.protocol in ("lldp", "both"):
            logger.debug("Fetching LLDP neighbor details")
            out = run_command(client, "show lldp neighbors detail")
            if out and "LLDP is not enabled" not in out and "Invalid input" not in out:
                found = parse_lldp_neighbors(out)
                logger.info("LLDP: %d neighbor(s)", len(found))
                neighbors.extend(found)
            else:
                logger.warning("LLDP unavailable or not enabled on %s", args.device)

        if args.json or args.output:
            result = {
                "device": args.device,
                "protocol": args.protocol,
                "neighbor_count": len(neighbors),
                "neighbors": [asdict(n) for n in neighbors],
            }
            json_str = json.dumps(result, indent=2)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(json_str)
                logger.info("Results written to %s", args.output)
            else:
                print(json_str)
        else:
            print_table(neighbors, args.device)

    finally:
        client.close()
        logger.debug("SSH connection closed")


if __name__ == "__main__":
    main()