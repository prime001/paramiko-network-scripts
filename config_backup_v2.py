Now I have the style reference. I'll write a CDP/LLDP neighbor discovery script — a practical topology mapping tool not covered by any existing script.

```
"""
cdp_neighbor_map.py - CDP/LLDP Neighbor Discovery and Topology Mapper

Connects to a Cisco (or LLDP-capable) device via SSH, retrieves neighbor
adjacency tables, and displays a structured view of directly connected
peers. Useful for verifying topology, auditing cabling, and bootstrapping
network documentation.

Supports both CDP (Cisco Discovery Protocol) and LLDP, with optional
recursive discovery that walks the graph one hop at a time.

Usage:
    python cdp_neighbor_map.py -d 192.168.1.1 -u admin -p secret
    python cdp_neighbor_map.py -d 10.0.0.1 -u admin --lldp --format json
    python cdp_neighbor_map.py -d 192.168.1.1 -u admin --output neighbors.json
    python cdp_neighbor_map.py -d 10.0.0.1 -u admin --recursive --max-depth 2

Prerequisites:
    pip install paramiko
    Device must have CDP or LLDP enabled and SSH accessible.
    Account requires privilege level to run 'show cdp neighbors detail'
    or 'show lldp neighbors detail'.
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Set

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class Neighbor:
    device_id: str
    local_interface: str
    remote_interface: str
    platform: str
    ip_address: str
    capabilities: str = ""


@dataclass
class DeviceNeighbors:
    host: str
    protocol: str
    neighbors: List[Neighbor] = field(default_factory=list)


def ssh_connect(
    host: str, username: str, password: str, port: int = 22
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        log.info("Connected to %s:%d", host, port)
        return client
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", host, exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Network error connecting to %s: %s", host, exc)
        sys.exit(1)


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.debug("stderr from device: %s", err)
        return output
    except paramiko.SSHException as exc:
        log.error("Command execution failed: %s", exc)
        return ""


def parse_cdp_neighbors(raw: str) -> List[Neighbor]:
    neighbors: List[Neighbor] = []
    # CDP detail output uses dashes as block separators
    blocks = re.split(r"-{3,}", raw)
    for block in blocks:
        if "Device ID" not in block:
            continue
        def extract(pattern: str, default: str = "") -> str:
            m = re.search(pattern, block, re.IGNORECASE)
            return m.group(1).strip() if m else default

        device_id = extract(r"Device ID:\s*(\S+)")
        ip = extract(r"IP(?:v4)? address:\s*([\d.]+)")
        platform = extract(r"Platform:\s*([^,\n]+)")
        capabilities = extract(r"Capabilities:\s*([^\n]+)")
        local_iface = extract(r"Interface:\s*(\S+),")
        remote_iface = extract(r"Port ID \(outgoing port\):\s*(\S+)")

        if device_id:
            neighbors.append(
                Neighbor(
                    device_id=device_id,
                    local_interface=local_iface,
                    remote_interface=remote_iface,
                    platform=platform.rstrip(",").strip(),
                    ip_address=ip,
                    capabilities=capabilities.strip(),
                )
            )
    return neighbors


def parse_lldp_neighbors(raw: str) -> List[Neighbor]:
    neighbors: List[Neighbor] = []
    blocks = re.split(r"-{3,}|={3,}", raw)
    for block in blocks:
        if "System Name" not in block and "Port ID" not in block:
            continue

        def extract(pattern: str, default: str = "") -> str:
            m = re.search(pattern, block, re.IGNORECASE)
            return m.group(1).strip() if m else default

        device_id = extract(r"System Name:\s*(\S+)")
        ip = extract(r"Management Addresses?[^\n]*\n\s*IP[^\n]*?:\s*([\d.]+)")
        platform = extract(r"System Description:\s*([^\n]+)")
        capabilities = extract(r"System Capabilities:\s*([^\n]+)")
        local_iface = extract(r"Local Interface:\s*(\S+)")
        remote_iface = extract(r"Port ID\s*:\s*(\S+)")

        if device_id:
            neighbors.append(
                Neighbor(
                    device_id=device_id,
                    local_interface=local_iface,
                    remote_interface=remote_iface,
                    platform=platform[:60] if platform else "",
                    ip_address=ip,
                    capabilities=capabilities.strip(),
                )
            )
    return neighbors


def collect_neighbors(
    host: str, username: str, password: str, port: int, use_lldp: bool
) -> DeviceNeighbors:
    client = ssh_connect(host, username, password, port)
    protocol = "lldp" if use_lldp else "cdp"
    command = (
        "show lldp neighbors detail" if use_lldp else "show cdp neighbors detail"
    )
    try:
        raw = run_command(client, command)
    finally:
        client.close()

    if not raw.strip():
        log.warning("Empty response from %s — %s may not be enabled", host, protocol.upper())
        return DeviceNeighbors(host=host, protocol=protocol)

    parse_fn = parse_lldp_neighbors if use_lldp else parse_cdp_neighbors
    neighbors = parse_fn(raw)
    log.info("Found %d %s neighbor(s) on %s", len(neighbors), protocol.upper(), host)
    return DeviceNeighbors(host=host, protocol=protocol, neighbors=neighbors)


def print_table(result: DeviceNeighbors) -> None:
    print(f"\n{result.protocol.upper()} Neighbors for {result.host}")
    print("=" * 72)
    if not result.neighbors:
        print("  No neighbors found.")
        return
    header = f"  {'Device ID':<28} {'Local Intf':<18} {'Remote Intf':<18} {'IP Address'}"
    print(header)
    print("  " + "-" * 68)
    for n in result.neighbors:
        print(
            f"  {n.device_id:<28} {n.local_interface:<18} {n.remote_interface:<18} {n.ip_address}"
        )
        if n.platform:
            print(f"    Platform: {n.platform}  |  Capabilities: {n.capabilities}")
    print(f"\n  Total: {len(result.neighbors)} neighbor(s)\n")


def recursive_discover(
    seed: str,
    username: str,
    password: str,
    port: int,
    use_lldp: bool,
    max_depth: int,
) -> Dict[str, DeviceNeighbors]:
    visited: Set[str] = set()
    topology: Dict[str, DeviceNeighbors] = {}
    queue = [(seed, 0)]

    while queue:
        host, depth = queue.pop(0)
        if host in visited or depth > max_depth:
            continue
        visited.add(host)

        result = collect_neighbors(host, username, password, port, use_lldp)
        topology[host] = result

        if depth < max_depth:
            for n in result.neighbors:
                if n.ip_address and n.ip_address not in visited:
                    queue.append((n.ip_address, depth + 1))

    return topology


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover and display CDP/LLDP neighbors from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--lldp", action="store_true", help="Use LLDP instead of CDP"
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Walk neighbors recursively (requires IP reachability to each peer)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=1,
        metavar="N",
        help="Maximum hop depth for recursive discovery (default: 1)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--output", metavar="FILE", help="Save JSON output to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    if args.recursive:
        topology = recursive_discover(
            args.device, args.username, password, args.port, args.lldp, args.max_depth
        )
        results = list(topology.values())
    else:
        result = collect_neighbors(
            args.device, args.username, password, args.port, args.lldp
        )
        results = [result]

    if args.format == "json" or args.output:
        data = [
            {"host": r.host, "protocol": r.protocol, "neighbors": [asdict(n) for n in r.neighbors]}
            for r in results
        ]
        json_str = json.dumps(data, indent=2)
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(json_str)
            log.info("Saved results to %s", args.output)
        if args.format == "json":
            print(json_str)
    else:
        for r in results:
            print_table(r)


if __name__ == "__main__":
    main()
```