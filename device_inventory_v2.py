cdp_lldp_neighbors.py - Discover and report CDP/LLDP network neighbors via SSH.

Purpose:
    Connects to a network device via SSH and retrieves CDP or LLDP neighbor
    information, giving a topology view of directly connected devices. Useful
    for auditing physical connectivity, validating cabling, and building
    network maps without requiring SNMP or a dedicated NMS.

Usage:
    python cdp_lldp_neighbors.py -H 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -H 192.168.1.1 -u admin -p secret --protocol lldp
    python cdp_lldp_neighbors.py -H 192.168.1.1 -u admin -p secret --output json

Prerequisites:
    - pip install paramiko
    - SSH access to the target device
    - CDP or LLDP enabled on the device (at least one must be active)
    - Tested against Cisco IOS/IOS-XE; LLDP mode is vendor-agnostic
"""

import argparse
import json
import logging
import re
import sys

import paramiko

LOG = logging.getLogger(__name__)


def run_command(ssh: paramiko.SSHClient, command: str, timeout: float = 30.0) -> str:
    """Execute a command over SSH and return decoded stdout."""
    _, stdout, _ = ssh.exec_command(command, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


def parse_cdp_neighbors(raw: str) -> list[dict]:
    """Parse 'show cdp neighbors detail' output into a list of neighbor dicts."""
    neighbors = []
    blocks = re.split(r"-{20,}", raw)
    for block in blocks:
        if "Device ID" not in block:
            continue
        neighbor: dict = {}

        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            neighbor["device_id"] = m.group(1)

        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            neighbor["ip_address"] = m.group(1)

        m = re.search(r"Platform:\s*([^,\n]+)", block)
        if m:
            neighbor["platform"] = m.group(1).strip()

        m = re.search(r"Interface:\s*(\S+),\s*Port ID[^:]*:\s*(\S+)", block)
        if m:
            neighbor["local_interface"] = m.group(1).rstrip(",")
            neighbor["remote_interface"] = m.group(2)

        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            neighbor["capabilities"] = m.group(1).strip()

        if "device_id" in neighbor:
            neighbors.append(neighbor)
    return neighbors


def parse_lldp_neighbors(raw: str) -> list[dict]:
    """Parse 'show lldp neighbors detail' output into a list of neighbor dicts."""
    neighbors = []
    blocks = re.split(r"-{10,}", raw)
    for block in blocks:
        if "Port id" not in block and "Local Intf" not in block:
            continue
        neighbor: dict = {}

        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            neighbor["device_id"] = m.group(1)

        m = re.search(r"(?:Management Addresses?|IP:)[^\d]*(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            neighbor["ip_address"] = m.group(1)

        m = re.search(r"System Description:\s*(.+?)(?:\n[ \t]*\n|\Z)", block, re.DOTALL)
        if m:
            neighbor["platform"] = " ".join(m.group(1).split())[:80]

        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            neighbor["local_interface"] = m.group(1)

        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            neighbor["remote_interface"] = m.group(1)

        m = re.search(r"System Capabilities:\s*(.+)", block)
        if m:
            neighbor["capabilities"] = m.group(1).strip()

        if "device_id" in neighbor or "local_interface" in neighbor:
            neighbors.append(neighbor)
    return neighbors


def collect_neighbors(
    host: str,
    username: str,
    password: str,
    port: int,
    protocol: str,
    timeout: int,
) -> tuple[list[dict], str]:
    """SSH to device and return (neighbors, protocol_used)."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        LOG.info("Connecting to %s:%d", host, port)
        ssh.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )

        if protocol in ("cdp", "auto"):
            LOG.info("Querying CDP neighbors")
            raw = run_command(ssh, "show cdp neighbors detail", timeout=timeout)
            neighbors = parse_cdp_neighbors(raw)
            if neighbors or protocol == "cdp":
                return neighbors, "CDP"

        LOG.info("Querying LLDP neighbors")
        raw = run_command(ssh, "show lldp neighbors detail", timeout=timeout)
        neighbors = parse_lldp_neighbors(raw)
        return neighbors, "LLDP"

    finally:
        ssh.close()


def print_table(neighbors: list[dict], protocol: str) -> None:
    """Render neighbors as a fixed-width ASCII table."""
    print(f"\nNeighbors discovered via {protocol}:\n")
    if not neighbors:
        print("  No neighbors found.")
        return

    cols = [
        ("device_id", "Device ID"),
        ("ip_address", "IP Address"),
        ("local_interface", "Local Intf"),
        ("remote_interface", "Remote Intf"),
        ("platform", "Platform"),
        ("capabilities", "Capabilities"),
    ]
    widths = [
        max(len(hdr), max(len(str(n.get(key, ""))) for n in neighbors))
        for key, hdr in cols
    ]
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    row_fmt = "| " + " | ".join(f"{{:<{w}}}" for w in widths) + " |"

    print(sep)
    print(row_fmt.format(*[hdr for _, hdr in cols]))
    print(sep)
    for n in neighbors:
        vals = [str(n.get(key, ""))[:w] for (key, _), w in zip(cols, widths)]
        print(row_fmt.format(*vals))
    print(sep)
    print(f"\nTotal: {len(neighbors)} neighbor(s)\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors on a network device via SSH.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument(
        "--protocol",
        choices=["cdp", "lldp", "auto"],
        default="auto",
        help="Neighbor protocol; 'auto' tries CDP then falls back to LLDP",
    )
    p.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout (seconds)")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        neighbors, protocol_used = collect_neighbors(
            host=args.host,
            username=args.username,
            password=args.password,
            port=args.port,
            protocol=args.protocol,
            timeout=args.timeout,
        )
        if args.output == "json":
            print(json.dumps({"protocol": protocol_used, "neighbors": neighbors}, indent=2))
        else:
            print_table(neighbors, protocol_used)
        sys.exit(0)
    except paramiko.AuthenticationException:
        LOG.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        LOG.error("SSH error connecting to %s: %s", args.host, exc)
        sys.exit(1)
    except OSError as exc:
        LOG.error("Network error connecting to %s: %s", args.host, exc)
        sys.exit(1)