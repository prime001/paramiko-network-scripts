```python
"""
cdp_neighbor_map.py - Collect and display CDP/LLDP neighbor topology from a network device.

Purpose:
    Connects to a Cisco IOS/IOS-XE device via SSH and retrieves CDP neighbor
    details to map adjacent devices. Useful for topology discovery, change
    validation, and pre/post-maintenance audits.

Usage:
    python cdp_neighbor_map.py -d 192.168.1.1 -u admin -p secret
    python cdp_neighbor_map.py -d 192.168.1.1 -u admin --lldp --json
    python cdp_neighbor_map.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa

Prerequisites:
    pip install paramiko
    CDP or LLDP must be enabled on the target device.
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time

import paramiko

LOG = logging.getLogger(__name__)


def run_command(shell, command, wait=1.5):
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.2)
    return output


def open_shell(client):
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(1)
    shell.recv(65535)
    run_command(shell, "terminal length 0", wait=0.5)
    return shell


def parse_cdp_neighbors(raw):
    neighbors = []
    blocks = re.split(r"-{10,}", raw)
    for block in blocks:
        if "Device ID" not in block:
            continue
        neighbor = {}
        m = re.search(r"Device ID:\s*(.+)", block)
        if m:
            neighbor["device_id"] = m.group(1).strip()
        m = re.search(r"IP address:\s*(\S+)", block)
        if not m:
            m = re.search(r"IPv4 Address:\s*(\S+)", block)
        neighbor["ip"] = m.group(1).strip() if m else "N/A"
        m = re.search(r"Platform:\s*([^,]+)", block)
        neighbor["platform"] = m.group(1).strip() if m else "N/A"
        m = re.search(r"Interface:\s*(\S+)", block)
        neighbor["local_intf"] = m.group(1).rstrip(",") if m else "N/A"
        m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)
        neighbor["remote_intf"] = m.group(1).strip() if m else "N/A"
        m = re.search(r"Software Version[^\n]*\n([^\n]+)", block)
        neighbor["software"] = m.group(1).strip() if m else "N/A"
        if neighbor.get("device_id"):
            neighbors.append(neighbor)
    return neighbors


def parse_lldp_neighbors(raw):
    neighbors = []
    blocks = re.split(r"-{10,}|(?=Local Intf)", raw)
    for block in blocks:
        if "System Name" not in block and "Chassis id" not in block:
            continue
        neighbor = {}
        m = re.search(r"System Name:\s*(.+)", block)
        neighbor["device_id"] = m.group(1).strip() if m else "N/A"
        m = re.search(r"Management Addresses[^\n]*\n\s*IP:\s*(\S+)", block)
        if not m:
            m = re.search(r"IP:\s*(\S+)", block)
        neighbor["ip"] = m.group(1).strip() if m else "N/A"
        m = re.search(r"System Description[^\n]*\n([^\n]+)", block)
        neighbor["platform"] = m.group(1).strip() if m else "N/A"
        m = re.search(r"Local Intf:\s*(\S+)", block)
        neighbor["local_intf"] = m.group(1).strip() if m else "N/A"
        m = re.search(r"Port id:\s*(\S+)", block)
        neighbor["remote_intf"] = m.group(1).strip() if m else "N/A"
        neighbor["software"] = "N/A"
        if neighbor.get("device_id") != "N/A":
            neighbors.append(neighbor)
    return neighbors


def print_table(neighbors, hostname):
    col_w = [30, 17, 18, 18, 40]
    header = ["Device ID", "Mgmt IP", "Local Intf", "Remote Intf", "Platform"]
    sep = "+-" + "-+-".join("-" * w for w in col_w) + "-+"
    row_fmt = "| " + " | ".join(f"{{:<{w}}}" for w in col_w) + " |"
    print(f"\nCDP/LLDP Neighbors — {hostname}")
    print(sep)
    print(row_fmt.format(*header))
    print(sep)
    for n in neighbors:
        print(row_fmt.format(
            n["device_id"][:col_w[0]],
            n["ip"][:col_w[1]],
            n["local_intf"][:col_w[2]],
            n["remote_intf"][:col_w[3]],
            n["platform"][:col_w[4]],
        ))
    print(sep)
    print(f"Total: {len(neighbors)} neighbor(s)\n")


def get_hostname(shell):
    out = run_command(shell, "show version | include hostname", wait=1.0)
    m = re.search(r"hostname\s+(\S+)", out, re.IGNORECASE)
    if m:
        return m.group(1)
    out2 = run_command(shell, "show running-config | include hostname", wait=1.0)
    m = re.search(r"hostname\s+(\S+)", out2, re.IGNORECASE)
    return m.group(1) if m else "unknown"


def collect_neighbors(args):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": args.device,
        "port": args.port,
        "username": args.username,
        "timeout": args.timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if args.key:
        connect_kwargs["key_filename"] = args.key
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = args.password

    LOG.debug("Connecting to %s:%s", args.device, args.port)
    client.connect(**connect_kwargs)

    try:
        shell = open_shell(client)
        hostname = get_hostname(shell)

        if args.lldp:
            LOG.debug("Collecting LLDP neighbors")
            raw = run_command(shell, "show lldp neighbors detail", wait=2.0)
            neighbors = parse_lldp_neighbors(raw)
        else:
            LOG.debug("Collecting CDP neighbors")
            raw = run_command(shell, "show cdp neighbors detail", wait=2.0)
            neighbors = parse_cdp_neighbors(raw)

        return hostname, neighbors
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Collect CDP/LLDP neighbor topology from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("-k", "--key", default=None, metavar="KEY_FILE", help="SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    parser.add_argument("--lldp", action="store_true", help="Use LLDP instead of CDP")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.key and args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        hostname, neighbors = collect_neighbors(args)
    except paramiko.AuthenticationException:
        LOG.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        LOG.error("Connection error: %s", exc)
        sys.exit(1)

    if not neighbors:
        proto = "LLDP" if args.lldp else "CDP"
        print(f"No {proto} neighbors found on {args.device}.")
        sys.exit(0)

    if args.as_json:
        payload = {"device": args.device, "hostname": hostname, "neighbors": neighbors}
        print(json.dumps(payload, indent=2))
    else:
        print_table(neighbors, hostname)


if __name__ == "__main__":
    main()
```