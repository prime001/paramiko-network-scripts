```python
"""
spanning_tree_parser.py - Cisco Spanning-Tree State Parser

Purpose:
    Connects to a Cisco IOS/IOS-XE switch via SSH and parses 'show spanning-tree'
    output into structured data. Identifies root bridges, port roles/states, and
    flags any topology-change events or ports in non-forwarding states.

Usage:
    python spanning_tree_parser.py -H 192.168.1.1 -u admin -p secret
    python spanning_tree_parser.py -H 192.168.1.1 -u admin --vlan 10,20 --json
    python spanning_tree_parser.py -H 192.168.1.1 -u admin --vlan all --warn-only

Prerequisites:
    pip install paramiko
    SSH access to target device with privilege level >= 1
    Cisco IOS or IOS-XE with spanning-tree enabled
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def ssh_command(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    """Execute a command and return stripped output."""
    channel = client.get_transport().open_session()
    channel.settimeout(timeout)
    channel.exec_command(command)
    output = b""
    while not channel.exit_status_ready():
        if channel.recv_ready():
            output += channel.recv(4096)
    while channel.recv_ready():
        output += channel.recv(4096)
    channel.close()
    return output.decode("utf-8", errors="replace").strip()


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info("Connecting to %s:%d", host, port)
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
    )
    return client


def parse_stp_block(block: str) -> dict:
    """Parse a single VLAN spanning-tree block into a dict."""
    result = {
        "vlan_id": None,
        "root_address": None,
        "root_priority": None,
        "bridge_address": None,
        "bridge_priority": None,
        "is_root": False,
        "ports": [],
    }

    vlan_match = re.search(r"VLAN(\d+)", block, re.IGNORECASE)
    if vlan_match:
        result["vlan_id"] = int(vlan_match.group(1))

    root_id = re.search(
        r"Root ID\s+Priority\s+(\d+).*?Address\s+([0-9a-f.]+)",
        block,
        re.IGNORECASE | re.DOTALL,
    )
    if root_id:
        result["root_priority"] = int(root_id.group(1))
        result["root_address"] = root_id.group(2)

    bridge_id = re.search(
        r"Bridge ID\s+Priority\s+(\d+).*?Address\s+([0-9a-f.]+)",
        block,
        re.IGNORECASE | re.DOTALL,
    )
    if bridge_id:
        result["bridge_priority"] = int(bridge_id.group(1))
        result["bridge_address"] = bridge_id.group(2)

    if result["root_address"] and result["bridge_address"]:
        result["is_root"] = result["root_address"].lower() == result["bridge_address"].lower()

    port_pattern = re.compile(
        r"^(\S+)\s+(Root|Desg|Altn|Back|BLK|FWD)\s+(FWD|BLK|LIS|LRN|BKN)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)",
        re.MULTILINE | re.IGNORECASE,
    )
    for m in port_pattern.finditer(block):
        result["ports"].append(
            {
                "interface": m.group(1),
                "role": m.group(2),
                "state": m.group(3).upper(),
                "cost": int(m.group(4)),
                "prio_nbr": m.group(5),
                "type": m.group(7),
            }
        )

    return result


def parse_stp_output(raw: str) -> list[dict]:
    blocks = re.split(r"(?=VLAN\d+)", raw, flags=re.IGNORECASE)
    results = []
    for block in blocks:
        block = block.strip()
        if not block or not re.match(r"VLAN\d+", block, re.IGNORECASE):
            continue
        parsed = parse_stp_block(block)
        if parsed["vlan_id"] is not None:
            results.append(parsed)
    return results


def warn_anomalies(vlan_data: list[dict]) -> list[str]:
    warnings = []
    for v in vlan_data:
        vid = v["vlan_id"]
        for port in v["ports"]:
            if port["state"] in ("BLK", "LIS", "LRN"):
                warnings.append(
                    f"VLAN {vid}: {port['interface']} is in {port['state']} state "
                    f"(role={port['role']})"
                )
        tc_match = re.search(r"topology change", str(v), re.IGNORECASE)
        if tc_match:
            warnings.append(f"VLAN {vid}: topology change detected")
    return warnings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Parse Cisco spanning-tree state from a live device."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument(
        "-p", "--password", default=None, help="SSH password (prompted if omitted)"
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--vlan",
        default="all",
        help="Comma-separated VLAN IDs to filter, or 'all' (default: all)",
    )
    p.add_argument(
        "--json", dest="output_json", action="store_true", help="Output results as JSON"
    )
    p.add_argument(
        "--warn-only",
        action="store_true",
        help="Only print anomaly warnings, suppress normal output",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    vlan_filter = None
    if args.vlan.lower() != "all":
        try:
            vlan_filter = {int(v.strip()) for v in args.vlan.split(",")}
        except ValueError:
            log.error("Invalid VLAN list: %s", args.vlan)
            return 1

    try:
        client = connect(args.host, args.port, args.username, password)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    try:
        log.info("Fetching spanning-tree data")
        raw = ssh_command(client, "show spanning-tree")
    finally:
        client.close()

    if not raw:
        log.error("Empty response from device")
        return 1

    vlan_data = parse_stp_output(raw)

    if vlan_filter:
        vlan_data = [v for v in vlan_data if v["vlan_id"] in vlan_filter]

    if not vlan_data:
        log.warning("No spanning-tree data found (check VLANs or STP mode)")
        return 0

    warnings = warn_anomalies(vlan_data)

    if args.output_json:
        out = {"host": args.host, "vlans": vlan_data, "warnings": warnings}
        print(json.dumps(out, indent=2))
        return 0

    if not args.warn_only:
        print(f"\nSpanning-Tree Summary for {args.host}")
        print("=" * 60)
        for v in vlan_data:
            root_marker = " [ROOT]" if v["is_root"] else ""
            print(
                f"  VLAN {v['vlan_id']:>4}{root_marker}  "
                f"bridge={v['bridge_address']}  "
                f"root={v['root_address']}  "
                f"ports={len(v['ports'])}"
            )

    if warnings:
        print("\nAnomalies detected:")
        for w in warnings:
            print(f"  WARNING: {w}")
    elif not args.warn_only:
        print("\nNo spanning-tree anomalies detected.")

    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
```