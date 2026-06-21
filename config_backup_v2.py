mac_table_collector.py - Collect and export the Layer 2 MAC address table from
Cisco IOS/IOS-XE network devices via SSH.

Purpose:
    Retrieves 'show mac address-table' output, parses each entry (VLAN, MAC,
    type, port), and exports results to CSV or formatted stdout. Useful for
    security audits, rogue device detection, port-to-MAC documentation, and
    correlating Layer-2 adjacency with ARP data.

Usage:
    python mac_table_collector.py -H 192.168.1.1 -u admin
    python mac_table_collector.py -H 192.168.1.1 -u admin -p secret --vlan 100
    python mac_table_collector.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa -o macs.csv
    python mac_table_collector.py -H 192.168.1.1 -u admin --vlan 10 --type DYNAMIC

Prerequisites:
    pip install paramiko
    SSH access to device; privilege level 1 (show commands) is sufficient.
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import csv
import getpass
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

# Matches Cisco IOS mac-address-table lines:
#   100   aabb.cc00.0100   DYNAMIC   Gi0/1
_MAC_LINE = re.compile(
    r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\w+)\s+([\w/\.:-]+)\s*$",
    re.IGNORECASE,
)


def ssh_connect(host, port, username, password=None, key_path=None, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_show_command(client, command, settle=2.5):
    shell = client.invoke_shell(width=250, height=5000)
    time.sleep(1.2)
    shell.recv(65535)  # drain login banner

    shell.send("terminal length 0\n")
    time.sleep(0.6)
    shell.recv(65535)

    shell.send(command + "\n")
    time.sleep(settle)

    buf = b""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if shell.recv_ready():
            buf += shell.recv(65535)
        elif buf:
            break
        time.sleep(0.2)

    shell.close()
    return buf.decode("utf-8", errors="replace")


def parse_mac_table(raw, vlan_filter=None, type_filter=None):
    entries = []
    for line in raw.splitlines():
        m = _MAC_LINE.match(line)
        if not m:
            continue
        vlan, mac, entry_type, port = m.groups()
        if vlan_filter and vlan != str(vlan_filter):
            continue
        if type_filter and entry_type.upper() != type_filter.upper():
            continue
        entries.append({"vlan": vlan, "mac": mac, "type": entry_type, "port": port})
    return entries


def print_table(entries):
    if not entries:
        print("No matching MAC address-table entries.")
        return
    print(f"{'VLAN':<6}  {'MAC Address':<17}  {'Type':<10}  Port")
    print("-" * 52)
    for e in entries:
        print(f"{e['vlan']:<6}  {e['mac']:<17}  {e['type']:<10}  {e['port']}")
    print(f"\n{len(entries)} entries.")


def write_csv(entries, filepath):
    with open(filepath, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["vlan", "mac", "type", "port"])
        writer.writeheader()
        writer.writerows(entries)
    log.info("Wrote %d entries to %s", len(entries), filepath)


def build_parser():
    p = argparse.ArgumentParser(
        description="Collect MAC address table from a Cisco IOS/IOS-XE device.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--key", dest="key_path", metavar="PATH", help="SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout (seconds)")
    p.add_argument("--vlan", metavar="ID", help="Filter results to a single VLAN")
    p.add_argument(
        "--type",
        dest="entry_type",
        metavar="TYPE",
        help="Filter by entry type, e.g. DYNAMIC or STATIC",
    )
    p.add_argument("-o", "--output", metavar="FILE", help="Write results to CSV file")
    p.add_argument("--debug", action="store_true", help="Enable verbose SSH debug output")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if not args.key_path and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = ssh_connect(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            key_path=args.key_path,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("SSH connection error: %s", exc)
        sys.exit(1)

    try:
        log.info("Retrieving MAC address table")
        raw = run_show_command(client, "show mac address-table")
        entries = parse_mac_table(raw, vlan_filter=args.vlan, type_filter=args.entry_type)
        log.info("Parsed %d entries", len(entries))
        if args.output:
            write_csv(entries, args.output)
        else:
            print_table(entries)
    except Exception as exc:
        log.error("Command execution failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()