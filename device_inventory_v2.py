```python
"""
mac_address_table.py - MAC Address Table Collector

Connects to a Cisco IOS/IOS-XE switch via SSH and retrieves the MAC address
table, optionally filtering by VLAN or interface. Results can be written to
CSV for asset tracking or troubleshooting.

Usage:
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret
    python mac_address_table.py -d 192.168.1.1 -u admin --vlan 100
    python mac_address_table.py -d 192.168.1.1 -u admin --interface Gi1/0/1
    python mac_address_table.py -d 192.168.1.1 -u admin --output mac_table.csv

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Account requires privilege level 1 or higher.
"""

import argparse
import csv
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def open_ssh_shell(hostname, username, password, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, hostname)
        raise
    except (paramiko.SSHException, OSError) as exc:
        log.error("Cannot connect to %s: %s", hostname, exc)
        raise

    shell = client.invoke_shell(width=220, height=50)
    time.sleep(1)
    shell.recv(4096)  # discard banner
    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(4096)
    return client, shell


def run_command(shell, command, wait=2.0):
    shell.send(command + "\n")
    time.sleep(wait)
    output = []
    while shell.recv_ready():
        chunk = shell.recv(65535).decode("utf-8", errors="replace")
        output.append(chunk)
        time.sleep(0.1)
    return "".join(output)


def parse_mac_table(raw_output):
    """
    Parse 'show mac address-table' output from Cisco IOS/IOS-XE.

    Expected line format:
      <vlan>   <mac>   <type>   <ports>
      10       aabb.cc00.0100   DYNAMIC  Gi1/0/2

    Returns a list of dicts with keys: vlan, mac, type, interface.
    """
    entries = []
    pattern = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
        r"(\S+)\s+"
        r"(\S+)",
        re.IGNORECASE,
    )
    for line in raw_output.splitlines():
        m = pattern.match(line)
        if m:
            entries.append(
                {
                    "vlan": m.group(1),
                    "mac": m.group(2).lower(),
                    "type": m.group(3).upper(),
                    "interface": m.group(4),
                }
            )
    return entries


def write_csv(entries, path):
    fieldnames = ["vlan", "mac", "type", "interface"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entries)
    log.info("Wrote %d entries to %s", len(entries), path)


def build_command(vlan=None, interface=None):
    base = "show mac address-table"
    if vlan:
        return f"{base} vlan {vlan}"
    if interface:
        return f"{base} interface {interface}"
    return base


def print_table(entries):
    if not entries:
        print("No MAC address entries found.")
        return
    header = f"{'VLAN':<6} {'MAC Address':<18} {'Type':<10} {'Interface'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(f"{e['vlan']:<6} {e['mac']:<18} {e['type']:<10} {e['interface']}")
    print(f"\nTotal entries: {len(entries)}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect MAC address table from a Cisco switch over SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vlan", help="Filter by VLAN ID")
    parser.add_argument("--interface", help="Filter by interface (e.g. Gi1/0/1)")
    parser.add_argument("--output", help="Write results to CSV file")
    parser.add_argument("--dynamic-only", action="store_true", help="Show only DYNAMIC entries")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password:
        import getpass
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    log.info("Connecting to %s", args.device)
    try:
        client, shell = open_ssh_shell(
            args.device, args.username, password, port=args.port
        )
    except Exception:
        sys.exit(1)

    try:
        cmd = build_command(vlan=args.vlan, interface=args.interface)
        log.info("Running: %s", cmd)
        raw = run_command(shell, cmd, wait=2.5)

        if args.debug:
            log.debug("Raw output:\n%s", raw)

        entries = parse_mac_table(raw)

        if args.dynamic_only:
            entries = [e for e in entries if e["type"] == "DYNAMIC"]

        if not entries:
            log.warning("No matching entries parsed from device output.")
        else:
            print_table(entries)
            if args.output:
                write_csv(entries, args.output)
    finally:
        shell.close()
        client.close()
        log.debug("SSH session closed.")
```