Looking at the existing scripts, I'll write a MAC address table lookup — distinct from `arp_table.py` (Layer 3 ARP) and not covered by any existing v2 scripts. It finds which switch port a device is physically connected to by MAC address, with optional ARP correlation for IP mapping.

```python
"""
MAC Address Table Lookup - paramiko-network-scripts

Purpose:
    Query the MAC address table on Cisco IOS/IOS-XE switches to locate where
    a specific device is physically connected. Supports filtering by MAC, VLAN,
    or interface, and optionally correlates with the ARP table to produce a
    MAC → IP → switch-port mapping in a single SSH session.

Usage:
    # Locate a specific device by MAC (any format accepted)
    python mac_table.py -H 192.168.1.1 -u admin --mac 00:1a:2b:3c:4d:5e

    # Show all MACs on VLAN 10 with their IP addresses
    python mac_table.py -H 192.168.1.1 -u admin --vlan 10 --arp

    # Show everything learned on a trunk port
    python mac_table.py -H 192.168.1.1 -u admin --interface Gi0/1

    # Full table dump
    python mac_table.py -H 192.168.1.1 -u admin

Prerequisites:
    pip install paramiko
    Cisco IOS/IOS-XE switch with SSH enabled (ip ssh version 2)
    Account with privilege level >= 1 (read-only is sufficient)
"""

import argparse
import getpass
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=10):
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
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", host, exc)
        raise
    except OSError as exc:
        log.error("Cannot reach %s:%d — %s", host, port, exc)
        raise


def run_command(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr for %r: %s", command, err)
    return output


def normalize_mac(mac):
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def cisco_mac_to_colon(mac_raw):
    digits = re.sub(r"\.", "", mac_raw)
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def parse_mac_table(output):
    entries = []
    # Cisco IOS: <vlan>  <mac (dotted)>  <type>  <port>
    pattern = re.compile(
        r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)",
        re.MULTILINE | re.IGNORECASE,
    )
    for m in pattern.finditer(output):
        vlan, mac_raw, mac_type, port = m.groups()
        entries.append({
            "vlan": int(vlan),
            "mac": cisco_mac_to_colon(mac_raw),
            "type": mac_type.lower(),
            "port": port,
        })
    return entries


def parse_arp_table(output):
    mapping = {}
    # Format: Internet  <ip>  <age>  <mac dotted>  ARPA  <iface>
    pattern = re.compile(
        r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+"
        r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
        re.MULTILINE | re.IGNORECASE,
    )
    for m in pattern.finditer(output):
        ip, mac_raw = m.groups()
        mapping[cisco_mac_to_colon(mac_raw)] = ip
    return mapping


def print_results(entries, arp_map=None):
    if not entries:
        print("No matching MAC table entries.")
        return

    col_widths = (6, 17, 8, 22, 16)
    headers = ("VLAN", "MAC Address", "Type", "Port", "IP Address")
    if arp_map is None:
        col_widths = col_widths[:4]
        headers = headers[:4]

    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
    separator = "  ".join("-" * w for w in col_widths)

    print(fmt.format(*headers))
    print(separator)
    for e in entries:
        row = [e["vlan"], e["mac"], e["type"], e["port"]]
        if arp_map is not None:
            row.append(arp_map.get(e["mac"], "—"))
        print(fmt.format(*row))

    noun = "entry" if len(entries) == 1 else "entries"
    print(f"\n{len(entries)} {noun} found.")


def main():
    parser = argparse.ArgumentParser(
        description="MAC address table lookup on Cisco switches via SSH"
    )
    parser.add_argument("-H", "--host", required=True, help="Switch hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--mac", help="Filter by MAC address (any delimiter format)")
    parser.add_argument("--vlan", type=int, help="Filter by VLAN ID")
    parser.add_argument("--interface", help="Filter by port name (e.g. Gi0/1, Te1/0/1)")
    parser.add_argument(
        "--arp", action="store_true",
        help="Correlate with ARP table to add IP address column"
    )
    parser.add_argument("--timeout", type=int, default=15, help="Per-command timeout (s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    filter_mac = None
    if args.mac:
        try:
            filter_mac = normalize_mac(args.mac)
        except ValueError as exc:
            log.error("%s", exc)
            sys.exit(1)

    try:
        log.info("Connecting to %s", args.host)
        client = ssh_connect(args.host, args.username, password, port=args.port)
    except Exception:
        sys.exit(1)

    try:
        log.info("Fetching MAC address table")
        raw = run_command(client, "show mac address-table", timeout=args.timeout)
        entries = parse_mac_table(raw)
        log.debug("Parsed %d raw MAC entries", len(entries))

        if filter_mac:
            entries = [e for e in entries if e["mac"] == filter_mac]
        if args.vlan is not None:
            entries = [e for e in entries if e["vlan"] == args.vlan]
        if args.interface:
            iface = args.interface.lower()
            entries = [e for e in entries if iface in e["port"].lower()]

        arp_map = None
        if args.arp:
            log.info("Fetching ARP table for IP correlation")
            arp_raw = run_command(client, "show ip arp", timeout=args.timeout)
            arp_map = parse_arp_table(arp_raw)
            log.debug("Parsed %d ARP entries", len(arp_map))

        print_results(entries, arp_map)

    finally:
        client.close()


if __name__ == "__main__":
    main()
```