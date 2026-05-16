The user's explicit instruction is "Output ONLY the script content" — that takes precedence over the brainstorming dialogue flow. Writing the script directly.

```
"""
cdp_neighbor_discovery.py - CDP/LLDP Neighbor Discovery via SSH

Purpose:
    Discovers directly connected neighbors on Cisco IOS/NX-OS devices using
    CDP (Cisco Discovery Protocol) or LLDP. Useful for topology documentation,
    change control, and network auditing when no NMS is available.

Usage:
    python cdp_neighbor_discovery.py -d 192.168.1.1 -u admin
    python cdp_neighbor_discovery.py -d 192.168.1.1 -u admin -p secret --protocol lldp
    python cdp_neighbor_discovery.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa --csv out.csv

Prerequisites:
    pip install paramiko
    SSH access to device; CDP or LLDP must be enabled globally
"""

import argparse
import csv
import getpass
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


def ssh_connect(host, port, username, password=None, key_file=None, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(shell, command, wait=2.0):
    shell.send(command + "\n")
    time.sleep(wait)
    buf = b""
    while shell.recv_ready():
        buf += shell.recv(65535)
    return buf.decode("utf-8", errors="replace")


def parse_cdp_neighbors(output):
    """Parse 'show cdp neighbors detail' into a list of neighbor dicts."""
    neighbors = []
    for block in re.split(r"-{10,}", output):
        if "Device ID" not in block:
            continue
        neighbor = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            neighbor["device_id"] = m.group(1)
        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            neighbor["ip_address"] = m.group(1)
        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            neighbor["platform"] = m.group(1).strip()
        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            neighbor["capabilities"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)", block)
        if m:
            neighbor["local_interface"] = m.group(1).rstrip(",")
            neighbor["remote_interface"] = m.group(2)
        m = re.search(r"Version\s*:\s*\n?(.*?)(?:\n\n|\Z)", block, re.DOTALL)
        if m:
            first_line = m.group(1).strip().splitlines()
            neighbor["version"] = first_line[0] if first_line else ""
        if "device_id" in neighbor:
            neighbors.append(neighbor)
    return neighbors


def parse_lldp_neighbors(output):
    """Parse 'show lldp neighbors detail' into a list of neighbor dicts."""
    neighbors = []
    for block in re.split(r"(?=Local Intf:)", output):
        if "System Name" not in block and "Port id" not in block:
            continue
        neighbor = {}
        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            neighbor["local_interface"] = m.group(1)
        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            neighbor["device_id"] = m.group(1)
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            neighbor["ip_address"] = m.group(1)
        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            neighbor["remote_interface"] = m.group(1)
        m = re.search(r"System Capabilities:\s*(.+)", block)
        if m:
            neighbor["capabilities"] = m.group(1).strip()
        m = re.search(r"System Description:\s*\n?(.*?)(?:\n\n|\Z)", block, re.DOTALL)
        if m:
            first_line = m.group(1).strip().splitlines()
            neighbor["version"] = first_line[0] if first_line else ""
        neighbor.setdefault("device_id", "unknown")
        if "local_interface" in neighbor:
            neighbors.append(neighbor)
    return neighbors


def collect_neighbors(host, port, username, password, key_file, protocol):
    log.info("Connecting to %s:%d", host, port)
    client = ssh_connect(host, port, username, password=password, key_file=key_file)
    shell = client.invoke_shell(width=250, height=200)
    time.sleep(1)
    shell.recv(65535)

    run_command(shell, "terminal length 0", wait=1.0)
    shell.recv(65535)

    if protocol == "cdp":
        log.info("Running: show cdp neighbors detail")
        output = run_command(shell, "show cdp neighbors detail", wait=3.0)
        neighbors = parse_cdp_neighbors(output)
    else:
        log.info("Running: show lldp neighbors detail")
        output = run_command(shell, "show lldp neighbors detail", wait=3.0)
        neighbors = parse_lldp_neighbors(output)

    client.close()
    return neighbors


def print_report(host, neighbors, protocol):
    print(f"\nNeighbor Discovery Report — {host} ({protocol.upper()})")
    print("=" * 80)
    if not neighbors:
        print("No neighbors found.")
        return
    print(f"{'Device ID':<30} {'Local Intf':<14} {'Remote Intf':<14} {'IP Address':<16} Platform")
    print("-" * 80)
    for n in neighbors:
        platform = n.get("platform") or n.get("capabilities", "")
        print(
            f"{n.get('device_id', ''):<30} "
            f"{n.get('local_interface', ''):<14} "
            f"{n.get('remote_interface', ''):<14} "
            f"{n.get('ip_address', ''):<16} "
            f"{platform}"
        )
    print(f"\nTotal neighbors: {len(neighbors)}")


def write_csv(path, host, neighbors):
    fields = ["device", "device_id", "ip_address", "local_interface",
              "remote_interface", "platform", "capabilities", "version"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for n in neighbors:
            writer.writerow({"device": host, **n})
    log.info("CSV written to %s", path)


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors on network devices via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_file", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Discovery protocol (default: cdp)",
    )
    parser.add_argument("--csv", dest="csv_file", default=None, help="Export results to CSV")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        neighbors = collect_neighbors(
            args.device, args.port, args.username,
            args.password, args.key_file, args.protocol,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    print_report(args.device, neighbors, args.protocol)
    if args.csv_file:
        write_csv(args.csv_file, args.device, neighbors)


if __name__ == "__main__":
    main()
```