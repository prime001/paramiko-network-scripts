CDP/LLDP Neighbor Discovery Tool

Connects to a network device via SSH and parses CDP (Cisco Discovery Protocol)
or LLDP (Link Layer Discovery Protocol) neighbor detail output into a structured
neighbor topology table. Useful for quickly mapping adjacencies during audits,
troubleshooting, or building topology documentation.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret --protocol lldp
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret --protocol both
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret --json

Prerequisites:
    pip install paramiko
    CDP or LLDP must be enabled on the target device.
    Tested against Cisco IOS, IOS-XE, and NX-OS.
"""

import argparse
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
    try:
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
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as e:
        logger.error("SSH error connecting to %s: %s", host, e)
        raise
    except Exception as e:
        logger.error("Connection failed to %s: %s", host, e)
        raise


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.debug("stderr: %s", err.strip())
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

        m = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\S+)", block)
        if not m:
            m = re.search(
                r"Entry address\(es\):\s*\n\s*IP(?:v4)? address:\s*(\S+)", block
            )
        if m:
            neighbor["ip_address"] = m.group(1).strip()

        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            neighbor["platform"] = m.group(1).strip()

        m = re.search(r"Interface:\s*(\S+)", block)
        if m:
            neighbor["local_interface"] = m.group(1).rstrip(",")

        m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)
        if m:
            neighbor["remote_interface"] = m.group(1).strip()

        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            neighbor["capabilities"] = m.group(1).strip()

        if neighbor.get("device_id"):
            neighbors.append(neighbor)

    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    blocks = re.split(r"-{5,}|={5,}", output)

    for block in blocks:
        if not block.strip():
            continue

        neighbor = {}

        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            neighbor["device_id"] = m.group(1).strip()

        m = re.search(
            r"Management [Aa]ddress(?:es)?:\s*\n\s*(\d+\.\d+\.\d+\.\d+)", block
        )
        if not m:
            m = re.search(
                r"Management [Aa]ddress[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", block
            )
        if m:
            neighbor["ip_address"] = m.group(1).strip()

        m = re.search(r"System Description:\s*\n\s*(.+)", block)
        if m:
            neighbor["platform"] = m.group(1).strip()[:60]

        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            neighbor["local_interface"] = m.group(1).strip()

        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            neighbor["remote_interface"] = m.group(1).strip()

        m = re.search(r"System Capabilities:\s*(.+)", block)
        if m:
            neighbor["capabilities"] = m.group(1).strip()

        if neighbor.get("device_id"):
            neighbors.append(neighbor)

    return neighbors


def print_table(neighbors, protocol):
    if not neighbors:
        print(f"No {protocol.upper()} neighbors found.")
        return

    headers = ["Device ID", "IP Address", "Local Intf", "Remote Intf", "Platform", "Capabilities"]
    col_keys = ["device_id", "ip_address", "local_interface", "remote_interface", "platform", "capabilities"]

    widths = [len(h) for h in headers]
    for n in neighbors:
        for i, key in enumerate(col_keys):
            widths[i] = max(widths[i], len(str(n.get(key, ""))))

    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    sep = "  ".join("-" * w for w in widths)

    print(f"\n{protocol.upper()} Neighbors ({len(neighbors)} found)")
    print(sep)
    print(fmt.format(*headers))
    print(sep)
    for n in neighbors:
        row = [str(n.get(k, "")) for k in col_keys]
        print(fmt.format(*row))
    print(sep)


def main():
    parser = argparse.ArgumentParser(
        description="Parse CDP/LLDP neighbor tables from network devices"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp", "both"],
        default="cdp",
        help="Discovery protocol to query (default: cdp)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--timeout", type=int, default=30, help="SSH timeout in seconds (default: 30)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logger.info("Connecting to %s", args.device)
        client = ssh_connect(
            args.device, args.username, args.password, args.port, args.timeout
        )
    except Exception:
        sys.exit(1)

    results = {}

    try:
        if args.protocol in ("cdp", "both"):
            logger.info("Fetching CDP neighbors detail")
            raw = run_command(client, "show cdp neighbors detail", args.timeout)
            results["cdp"] = parse_cdp_neighbors(raw)
            logger.info("Found %d CDP neighbor(s)", len(results["cdp"]))

        if args.protocol in ("lldp", "both"):
            logger.info("Fetching LLDP neighbors detail")
            raw = run_command(client, "show lldp neighbors detail", args.timeout)
            results["lldp"] = parse_lldp_neighbors(raw)
            logger.info("Found %d LLDP neighbor(s)", len(results["lldp"]))
    finally:
        client.close()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for protocol, neighbors in results.items():
            print_table(neighbors, protocol)


if __name__ == "__main__":
    main()