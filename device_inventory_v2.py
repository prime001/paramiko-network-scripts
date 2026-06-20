The write was blocked by permissions. The script is ready — here it is:

```python
"""
cdp_lldp_neighbors.py - CDP/LLDP Neighbor Discovery via SSH

Connects to a network device over SSH and retrieves CDP and/or LLDP neighbor
information, presenting a structured view of directly connected peers. Useful
for building topology maps and auditing network adjacencies.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret --protocol lldp
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --protocol both --json

Prerequisites:
    pip install paramiko
    CDP or LLDP must be enabled on the target Cisco IOS/NX-OS device.
    SSH access required with privilege level 1 or higher.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as e:
        logger.error("SSH error connecting to %s: %s", host, e)
        raise
    except OSError as e:
        logger.error("Network error connecting to %s: %s", host, e)
        raise


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    if error.strip():
        logger.debug("stderr from '%s': %s", command, error.strip())
    return output


def parse_cdp_neighbors(output):
    neighbors = []
    blocks = re.split(r"-{5,}", output)
    for block in blocks:
        if not block.strip():
            continue
        neighbor = {}
        m = re.search(r"Device ID:\s*(.+)", block)
        if m:
            neighbor["device_id"] = m.group(1).strip()
        m = re.search(r"IP(?:v4)? address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            neighbor["ip_address"] = m.group(1).strip()
        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            neighbor["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),\s*Port ID[^:]*:\s*(\S+)", block)
        if m:
            neighbor["local_interface"] = m.group(1).strip()
            neighbor["remote_interface"] = m.group(2).strip()
        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            neighbor["capabilities"] = m.group(1).strip()
        m = re.search(r"Version\s*:\s*\n(.+)", block)
        if m:
            neighbor["software_version"] = m.group(1).strip()
        if neighbor.get("device_id"):
            neighbors.append(neighbor)
    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    blocks = re.split(r"-{5,}", output)
    for block in blocks:
        if not block.strip():
            continue
        neighbor = {}
        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            neighbor["device_id"] = m.group(1).strip()
        m = re.search(r"Management Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            neighbor["ip_address"] = m.group(1).strip()
        m = re.search(r"System Description[^:]*:\s*\n(.+)", block)
        if m:
            neighbor["platform"] = m.group(1).strip()
        m = re.search(r"Local Intf(?:erface)?:\s*(\S+)", block)
        if m:
            neighbor["local_interface"] = m.group(1).strip()
        m = re.search(r"Port (?:id|ID):\s*(\S+)", block)
        if m:
            neighbor["remote_interface"] = m.group(1).strip()
        m = re.search(r"System Capabilit(?:y|ies)[^:]*:\s*(.+)", block)
        if m:
            neighbor["capabilities"] = m.group(1).strip()
        if neighbor.get("device_id"):
            neighbors.append(neighbor)
    return neighbors


def print_table(neighbors, protocol):
    if not neighbors:
        print(f"No {protocol.upper()} neighbors found.")
        return
    print(f"\n{'=' * 72}")
    print(f"  {protocol.upper()} Neighbors  ({len(neighbors)} found)")
    print(f"{'=' * 72}")
    print(f"{'Device ID':<32} {'IP Address':<16} {'Local Intf':<14} {'Remote Intf'}")
    print("-" * 72)
    for n in neighbors:
        device_id = n.get("device_id", "N/A")[:31]
        ip = n.get("ip_address", "N/A")[:15]
        local = n.get("local_interface", "N/A")[:13]
        remote = n.get("remote_interface", "N/A")
        print(f"{device_id:<32} {ip:<16} {local:<14} {remote}")
        if n.get("platform"):
            print(f"    Platform    : {n['platform'][:62]}")
        if n.get("capabilities"):
            print(f"    Capabilities: {n['capabilities'][:62]}")
        if n.get("software_version"):
            print(f"    Version     : {n['software_version'][:62]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Retrieve CDP/LLDP neighbor info from a network device over SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp", "both"], default="cdp",
        help="Neighbor discovery protocol to query (default: cdp)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="output_json",
        help="Emit results as JSON instead of a table",
    )
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    try:
        client = ssh_connect(args.device, args.username, password, args.port, args.timeout)
    except Exception as e:
        print(f"ERROR: Could not connect to {args.device}: {e}", file=sys.stderr)
        sys.exit(1)

    results = {}
    try:
        if args.protocol in ("cdp", "both"):
            results["cdp"] = parse_cdp_neighbors(
                run_command(client, "show cdp neighbors detail", args.timeout)
            )
        if args.protocol in ("lldp", "both"):
            results["lldp"] = parse_lldp_neighbors(
                run_command(client, "show lldp neighbors detail", args.timeout)
            )
    except Exception as e:
        print(f"ERROR: Command execution failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

    if args.output_json:
        print(json.dumps(results, indent=2))
    else:
        for proto, neighbors in results.items():
            print_table(neighbors, proto)


if __name__ == "__main__":
    main()
```

This is a **CDP/LLDP neighbor discovery** script (~190 lines) that fills a clear gap in the existing collection. It:

- SSHes to a device via paramiko and runs `show cdp/lldp neighbors detail`
- Parses block-delimited neighbor entries with regex (device ID, IP, platform, interfaces, capabilities, software version)
- Supports `--protocol cdp|lldp|both` to query either or both protocols
- Outputs a formatted table by default or `--json` for piping into other tools
- Handles auth errors, SSH errors, and network failures distinctly with proper exit codes