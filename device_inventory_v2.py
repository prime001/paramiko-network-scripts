neighbor_discovery.py - CDP/LLDP Network Neighbor Discovery

Purpose:
    Connects to a Cisco IOS/NX-OS device via SSH and collects CDP or LLDP
    neighbor detail to produce a local topology snapshot. Results print as a
    formatted table and optionally export as JSON or CSV for CMDB import or
    network documentation.

Usage:
    python neighbor_discovery.py -d 192.168.1.1 -u admin -p secret
    python neighbor_discovery.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa --protocol lldp
    python neighbor_discovery.py -d 192.168.1.1 -u admin -p secret --output neighbors.json
    python neighbor_discovery.py -d 192.168.1.1 -u admin -p secret --output neighbors.csv --format csv

Prerequisites:
    pip install paramiko
    SSH access to target device with CDP or LLDP enabled.
"""

import argparse
import csv
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


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username, timeout=timeout)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=20):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.debug("stderr for %r: %s", command, err.strip())
    return out


def parse_cdp_detail(raw):
    neighbors = []
    for block in re.split(r"-{10,}", raw):
        if not block.strip():
            continue
        n = {}
        m = re.search(r"Device ID:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["mgmt_ip"] = m.group(1)
        m = re.search(r"Platform:\s*(.+?),\s*Capabilities:", block, re.DOTALL)
        if m:
            n["platform"] = " ".join(m.group(1).split())
        m = re.search(r"Interface:\s*(\S+),\s*Port ID[^:]*:\s*(\S+)", block)
        if m:
            n["local_intf"] = m.group(1).rstrip(",")
            n["remote_intf"] = m.group(2).rstrip(",")
        m = re.search(r"Version\s*:\s*(.+?)(?=\n\S|\Z)", block, re.DOTALL)
        if m:
            n["software"] = " ".join(m.group(1).split())[:100]
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def parse_lldp_detail(raw):
    neighbors = []
    for block in re.split(r"(?=^-{3,}|\nLocal Intf)", raw, flags=re.MULTILINE):
        if not block.strip():
            continue
        n = {}
        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"Management Address[es]*:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["mgmt_ip"] = m.group(1)
        m = re.search(r"System Description[^:]*:\s*(.+?)(?=\n\S|\Z)", block, re.DOTALL)
        if m:
            n["platform"] = " ".join(m.group(1).split())[:80]
        m = re.search(r"Local Intf[a-z]*:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["local_intf"] = m.group(1)
        m = re.search(r"Port id[^:]*:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["remote_intf"] = m.group(1)
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def collect_neighbors(client, protocol):
    if protocol == "cdp":
        return parse_cdp_detail(run_command(client, "show cdp neighbors detail"))
    return parse_lldp_detail(run_command(client, "show lldp neighbors detail"))


def print_table(neighbors, host):
    print(f"\nNeighbors discovered from {host} ({len(neighbors)} total)\n")
    hdr = f"{'Device ID':<36} {'Local Intf':<18} {'Remote Intf':<18} {'Mgmt IP':<16} {'Platform':<28}"
    print(hdr)
    print("-" * len(hdr))
    for n in neighbors:
        print(
            f"{n.get('device_id', 'N/A'):<36}"
            f"{n.get('local_intf', 'N/A'):<18}"
            f"{n.get('remote_intf', 'N/A'):<18}"
            f"{n.get('mgmt_ip', 'N/A'):<16}"
            f"{n.get('platform', 'N/A')[:27]:<28}"
        )


def save_output(neighbors, path, fmt):
    if fmt == "json":
        with open(path, "w") as fh:
            json.dump(neighbors, fh, indent=2)
    else:
        fields = ["device_id", "local_intf", "remote_intf", "mgmt_ip", "platform", "software"]
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(neighbors)
    logger.info("Saved %s output to %s", fmt.upper(), path)


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors from a network device via SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_file", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Discovery protocol (default: cdp)",
    )
    parser.add_argument("--output", default=None, help="Save results to this file path")
    parser.add_argument(
        "--format", choices=["json", "csv"], default="json",
        help="Output file format when --output is set (default: json)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        parser.error("Provide --password or --key for authentication.")

    logger.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = ssh_connect(
            host=args.device,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        logger.info("Querying %s neighbors...", args.protocol.upper())
        neighbors = collect_neighbors(client, args.protocol)
    except Exception as exc:
        logger.error("Command execution failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    if not neighbors:
        logger.warning(
            "No neighbors found. Confirm %s is enabled on %s.",
            args.protocol.upper(), args.device,
        )
        sys.exit(0)

    print_table(neighbors, args.device)

    if args.output:
        save_output(neighbors, args.output, args.format)


if __name__ == "__main__":
    main()