CDP/LLDP Neighbor Discovery and Topology Mapper

Connects to a network device via SSH, collects CDP and/or LLDP neighbor
information, parses the structured output, and produces a topology map
suitable for documentation, troubleshooting, or automated inventory.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --ask-pass --protocol lldp
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret --output json
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret --output csv -o neighbors.csv

Prerequisites:
    pip install paramiko
    Device must have CDP and/or LLDP enabled and SSH accessible.
    Account requires at least privilege 1 (show commands only).
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass
from typing import List, Optional

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


@dataclass
class Neighbor:
    local_port: str
    device_id: str
    remote_port: str
    platform: str
    software_version: str
    ip_address: str
    capabilities: str
    protocol: str  # "cdp" or "lldp"


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    channel = client.invoke_shell()
    channel.settimeout(timeout)
    time.sleep(0.5)
    channel.recv(65535)  # drain banner/prompt

    channel.send(command + "\n")
    time.sleep(2)

    output = []
    while channel.recv_ready():
        chunk = channel.recv(65535).decode("utf-8", errors="replace")
        output.append(chunk)
        time.sleep(0.3)

    channel.close()
    return "".join(output)


def parse_cdp_neighbors(raw: str) -> List[Neighbor]:
    neighbors: List[Neighbor] = []
    blocks = re.split(r"-{10,}", raw)

    for block in blocks:
        if "Device ID" not in block:
            continue

        def extract(pattern: str, default: str = "") -> str:
            m = re.search(pattern, block, re.IGNORECASE)
            return m.group(1).strip() if m else default

        device_id = extract(r"Device ID:\s*(.+)")
        ip_address = extract(r"IP(?:v4)? address:\s*(\S+)")
        platform = extract(r"Platform:\s*([^,\n]+)")
        capabilities = extract(r"Capabilities:\s*(.+)")
        local_port = extract(r"Interface:\s*(\S+)")
        remote_port = extract(r"Port ID \(outgoing port\):\s*(.+)")
        software_version = extract(r"Version\s*:\s*(.+)")
        if not software_version:
            software_version = extract(r"(Cisco IOS[^\n]+)")

        if device_id:
            neighbors.append(
                Neighbor(
                    local_port=local_port,
                    device_id=device_id,
                    remote_port=remote_port,
                    platform=platform,
                    software_version=software_version[:80] if software_version else "",
                    ip_address=ip_address,
                    capabilities=capabilities,
                    protocol="cdp",
                )
            )

    return neighbors


def parse_lldp_neighbors(raw: str) -> List[Neighbor]:
    neighbors: List[Neighbor] = []
    blocks = re.split(r"-{10,}", raw)

    for block in blocks:
        if "System Name" not in block and "Port Description" not in block:
            continue

        def extract(pattern: str, default: str = "") -> str:
            m = re.search(pattern, block, re.IGNORECASE)
            return m.group(1).strip() if m else default

        device_id = extract(r"System Name:\s*(.+)")
        if not device_id:
            device_id = extract(r"Chassis id:\s*(.+)")
        ip_address = extract(r"IP:\s*(\S+)")
        platform = extract(r"System Description:\s*(.+)")
        capabilities = extract(r"System Capabilities:\s*(.+)")
        local_port = extract(r"Local (?:Interface|Intf):\s*(\S+)")
        remote_port = extract(r"Port id:\s*(.+)")

        if device_id:
            neighbors.append(
                Neighbor(
                    local_port=local_port,
                    device_id=device_id,
                    remote_port=remote_port,
                    platform=platform[:80] if platform else "",
                    software_version="",
                    ip_address=ip_address,
                    capabilities=capabilities,
                    protocol="lldp",
                )
            )

    return neighbors


def print_table(neighbors: List[Neighbor]) -> None:
    if not neighbors:
        print("No neighbors found.")
        return

    header = (
        f"{'Proto':<5} {'Local Port':<22} {'Device ID':<30} "
        f"{'Remote Port':<22} {'IP Address':<17} {'Platform':<30}"
    )
    print(header)
    print("-" * len(header))
    for n in neighbors:
        print(
            f"{n.protocol.upper():<5} {n.local_port:<22} {n.device_id:<30} "
            f"{n.remote_port:<22} {n.ip_address:<17} {n.platform[:29]:<30}"
        )


def write_json(neighbors: List[Neighbor], path: Optional[str]) -> None:
    data = [asdict(n) for n in neighbors]
    text = json.dumps(data, indent=2)
    if path:
        with open(path, "w") as f:
            f.write(text)
        log.info("JSON written to %s", path)
    else:
        print(text)


def write_csv(neighbors: List[Neighbor], path: Optional[str]) -> None:
    fields = list(asdict(neighbors[0]).keys()) if neighbors else []
    dest = open(path, "w", newline="") if path else sys.stdout
    try:
        writer = csv.DictWriter(dest, fieldnames=fields)
        writer.writeheader()
        for n in neighbors:
            writer.writerow(asdict(n))
    finally:
        if path:
            dest.close()
            log.info("CSV written to %s", path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect and parse CDP/LLDP neighbor data from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (omit to prompt)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp", "both"],
        default="both",
        help="Neighbor discovery protocol to query (default: both)",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("-o", "--outfile", default=None, help="Write output to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    log.info("Connecting to %s:%s", args.device, args.port)
    try:
        client = ssh_connect(args.device, args.username, password, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    neighbors: List[Neighbor] = []

    try:
        if args.protocol in ("cdp", "both"):
            log.info("Running: show cdp neighbors detail")
            raw_cdp = run_command(client, "show cdp neighbors detail")
            cdp_neighbors = parse_cdp_neighbors(raw_cdp)
            log.info("Found %d CDP neighbor(s)", len(cdp_neighbors))
            neighbors.extend(cdp_neighbors)

        if args.protocol in ("lldp", "both"):
            log.info("Running: show lldp neighbors detail")
            raw_lldp = run_command(client, "show lldp neighbors detail")
            lldp_neighbors = parse_lldp_neighbors(raw_lldp)
            log.info("Found %d LLDP neighbor(s)", len(lldp_neighbors))
            neighbors.extend(lldp_neighbors)
    finally:
        client.close()

    if not neighbors:
        log.warning("No neighbors discovered. Verify CDP/LLDP is enabled on the device.")
        sys.exit(0)

    if args.output == "table":
        print_table(neighbors)
    elif args.output == "json":
        write_json(neighbors, args.outfile)
    elif args.output == "csv":
        write_csv(neighbors, args.outfile)


if __name__ == "__main__":
    main()