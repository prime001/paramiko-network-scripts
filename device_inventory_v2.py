```python
"""
mac_table.py - Switch MAC Address Table Collector

Connects to a Cisco IOS/IOS-XE switch via SSH and retrieves the MAC address
table, parsing entries by VLAN, MAC address, entry type, and port. Distinct
from arp_table.py which maps IP→MAC; this maps MAC→switchport for L2 tracing.

Usage:
    python mac_table.py -d 192.168.1.1 -u admin -p secret
    python mac_table.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa --vlan 10
    python mac_table.py -d 192.168.1.1 -u admin -p secret --format csv -o macs.csv
    python mac_table.py -d 192.168.1.1 -u admin -p secret --interface Gi0/1

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Read-only privilege (show commands) is sufficient.
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_path=None, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_path),
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Either --password or --key must be provided")
    client.connect(**kwargs)
    return client


def run_show_command(client, command, settle=1.5):
    shell = client.invoke_shell()
    shell.settimeout(20)
    time.sleep(0.4)
    if shell.recv_ready():
        shell.recv(4096)

    shell.send("terminal length 0\n")
    time.sleep(0.3)
    if shell.recv_ready():
        shell.recv(4096)

    shell.send(command + "\n")
    time.sleep(settle)

    output = ""
    deadline = time.time() + 10
    while time.time() < deadline:
        if shell.recv_ready():
            output += shell.recv(8192).decode("utf-8", errors="replace")
            time.sleep(0.2)
        else:
            break

    shell.close()
    return output


def parse_mac_table(output):
    """Parse Cisco IOS 'show mac address-table' output into a list of dicts."""
    entries = []
    # Matches lines like:   10  aabb.cc00.0100  DYNAMIC  Gi0/1
    pattern = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(\w+)\s+"
        r"([\w/.\-]+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        vlan, mac, entry_type, port = m.groups()
        entries.append({
            "vlan": int(vlan),
            "mac": mac.lower(),
            "type": entry_type.upper(),
            "port": port,
        })
    return entries


def apply_filters(entries, vlan=None, interface=None, entry_type=None):
    if vlan is not None:
        entries = [e for e in entries if e["vlan"] == vlan]
    if interface:
        needle = interface.lower()
        entries = [e for e in entries if needle in e["port"].lower()]
    if entry_type:
        entries = [e for e in entries if e["type"] == entry_type.upper()]
    return entries


def print_table(entries):
    if not entries:
        print("No entries matched.")
        return
    print(f"{'VLAN':<6} {'MAC Address':<18} {'Type':<10} Port")
    print("-" * 50)
    for e in entries:
        print(f"{e['vlan']:<6} {e['mac']:<18} {e['type']:<10} {e['port']}")
    print(f"\n{len(entries)} entries")


def write_csv(entries, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["vlan", "mac", "type", "port"])
        w.writeheader()
        w.writerows(entries)
    log.info("Wrote %d entries to %s", len(entries), path)


def build_parser():
    p = argparse.ArgumentParser(description="Retrieve switch MAC address table via SSH")
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--key", default=None, metavar="PATH", help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--vlan", type=int, default=None, help="Filter by VLAN ID")
    p.add_argument("--interface", default=None, help="Filter by interface (partial match)")
    p.add_argument(
        "--type", dest="entry_type", choices=["DYNAMIC", "STATIC"],
        default=None, help="Filter by entry type",
    )
    p.add_argument(
        "--format", choices=["table", "json", "csv"], default="table",
        help="Output format (default: table)",
    )
    p.add_argument("-o", "--output", default=None, help="Output file for csv/json")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main():
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if not args.password and not args.key:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(
            host=args.device,
            username=args.username,
            password=args.password,
            key_path=args.key,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Running 'show mac address-table'")
        raw = run_show_command(client, "show mac address-table")
    except Exception as exc:
        log.error("Command execution failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    entries = parse_mac_table(raw)
    if not entries:
        log.warning("No MAC table entries parsed — verify device type and connectivity")
        log.debug("Raw output:\n%s", raw)

    entries = apply_filters(entries, vlan=args.vlan, interface=args.interface, entry_type=args.entry_type)

    if args.format == "table":
        print_table(entries)
    elif args.format == "json":
        payload = json.dumps(entries, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(payload)
            log.info("JSON written to %s", args.output)
        else:
            print(payload)
    elif args.format == "csv":
        if args.output:
            write_csv(entries, args.output)
        else:
            w = csv.DictWriter(sys.stdout, fieldnames=["vlan", "mac", "type", "port"])
            w.writeheader()
            w.writerows(entries)


if __name__ == "__main__":
    main()
```