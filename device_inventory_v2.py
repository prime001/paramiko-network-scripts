```python
"""
cdp_neighbor_map.py - Network topology discovery via CDP/LLDP neighbor tables

Purpose:
    Connects to a Cisco device via SSH and collects CDP and/or LLDP neighbor
    information to build a local topology map. Useful for automated network
    documentation, pre-change topology snapshots, and discovering undocumented
    adjacencies before maintenance windows.

Usage:
    python cdp_neighbor_map.py -H 192.168.1.1 -u admin -p secret
    python cdp_neighbor_map.py -H 192.168.1.1 -u admin --protocol lldp
    python cdp_neighbor_map.py -H 192.168.1.1 -u admin --protocol both --format json

Prerequisites:
    pip install paramiko
    CDP or LLDP must be enabled on the target device.
    SSH user needs privilege to run 'show cdp/lldp neighbors detail'.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
logger = logging.getLogger(__name__)


def ssh_exec(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        logger.debug("stderr for %r: %s", command, err)
    return out


def parse_cdp_neighbors(raw):
    neighbors = []
    for block in re.split(r"-{10,}", raw):
        if "Device ID" not in block:
            continue
        n = {"protocol": "CDP"}
        m = re.search(r"Device ID:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            n["platform"] = m.group(1).strip()[:40]
        m = re.search(r"Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)", block)
        if m:
            n["local_intf"] = m.group(1)
            n["remote_intf"] = m.group(2)
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def parse_lldp_neighbors(raw):
    neighbors = []
    for block in re.split(r"-{10,}", raw):
        if "System Name" not in block and "Port id" not in block:
            continue
        n = {"protocol": "LLDP"}
        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"Management Addresses.*?IP:\s*(\S+)", block, re.DOTALL)
        if not m:
            m = re.search(r"\bIP:\s*(\S+)", block)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"System Description.*?:\s*(.*?)(?=\n\n|\Z)", block, re.DOTALL)
        if m:
            n["platform"] = " ".join(m.group(1).split())[:40]
        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            n["local_intf"] = m.group(1)
        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            n["remote_intf"] = m.group(1)
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def print_table(local_device, neighbors):
    keys = ["device_id", "ip_address", "local_intf", "remote_intf", "platform", "protocol"]
    headers = ["Device ID", "IP Address", "Local Intf", "Remote Intf", "Platform", "Proto"]
    widths = [
        max(len(h), max((len(str(n.get(k, ""))) for n in neighbors), default=0))
        for h, k in zip(headers, keys)
    ]
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    row_fmt = lambda vals: "| " + " | ".join(str(v).ljust(w) for v, w in zip(vals, widths)) + " |"

    print(f"\nCDP/LLDP topology for {local_device}:")
    print(sep)
    print(row_fmt(headers))
    print(sep)
    for n in neighbors:
        print(row_fmt([n.get(k, "") for k in keys]))
    print(sep)
    print(f"\nTotal: {len(neighbors)} neighbor(s)")


def connect(host, port, username, password, key_file):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username, timeout=20)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs.update(password=password, look_for_keys=False, allow_agent=False)
    client.connect(**kwargs)
    return client


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors and output a topology map.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("-k", "--key-file", help="SSH private key file")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--protocol", choices=["cdp", "lldp", "both"], default="cdp")
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_file:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        client = connect(args.host, args.port, args.username, password, args.key_file)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except Exception as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        version_out = ssh_exec(client, "show version | include uptime")
        local_device = args.host
        m = re.search(r"^(\S+)\s+uptime", version_out, re.MULTILINE)
        if m:
            local_device = m.group(1)

        neighbors = []
        if args.protocol in ("cdp", "both"):
            raw = ssh_exec(client, "show cdp neighbors detail")
            found = parse_cdp_neighbors(raw)
            logger.debug("CDP: found %d neighbors", len(found))
            neighbors.extend(found)
        if args.protocol in ("lldp", "both"):
            raw = ssh_exec(client, "show lldp neighbors detail")
            found = parse_lldp_neighbors(raw)
            logger.debug("LLDP: found %d neighbors", len(found))
            neighbors.extend(found)
    finally:
        client.close()

    if not neighbors:
        print(f"No {args.protocol.upper()} neighbors found on {local_device}.")
        sys.exit(0)

    if args.format == "json":
        print(json.dumps({"local_device": local_device, "neighbors": neighbors}, indent=2))
    else:
        print_table(local_device, neighbors)


if __name__ == "__main__":
    main()
```