mac_address_table.py — Collect and filter MAC address table entries from network switches.

Usage:
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret --vlan 10
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret --mac 00:1a:2b:3c:4d:5e
    python mac_address_table.py -d 192.168.1.1 -u admin -p secret --type DYNAMIC --json

Prerequisites:
    pip install paramiko
    Target must support SSH and respond to 'show mac address-table' (Cisco IOS / NX-OS).
    SSH must be enabled: 'ip ssh version 2' and 'crypto key generate rsa modulus 2048'.
"""

import argparse
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
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
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", host, exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Connection to %s failed: %s", host, exc)
        sys.exit(1)


def run_command(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.warning("stderr from device: %s", err)
    return output


def parse_mac_table(output):
    """Parse Cisco IOS/NX-OS 'show mac address-table' into structured records."""
    entries = []
    # Matches: VLAN  MAC_ADDR  TYPE  PORTS — handles both IOS and NX-OS spacing
    pattern = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(\S+)\s+"
        r"(\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        vlan, mac, entry_type, port = match.groups()
        entries.append({
            "vlan": int(vlan),
            "mac": mac.lower(),
            "type": entry_type.upper(),
            "port": port,
        })
    return entries


def normalize_mac(mac_str):
    """Accept any common MAC format and return Cisco dotted-hex for comparison."""
    clean = re.sub(r"[:\-\.\s]", "", mac_str).lower()
    if len(clean) != 12 or not re.fullmatch(r"[0-9a-f]{12}", clean):
        return None
    return f"{clean[0:4]}.{clean[4:8]}.{clean[8:12]}"


def print_table(entries):
    if not entries:
        print("No matching MAC address table entries.")
        return
    col = f"{'VLAN':<6} {'MAC Address':<18} {'Type':<10} {'Port'}"
    print(col)
    print("-" * len(col))
    for e in entries:
        print(f"{e['vlan']:<6} {e['mac']:<18} {e['type']:<10} {e['port']}")
    print(f"\n{len(entries)} entries")


def main():
    parser = argparse.ArgumentParser(
        description="Retrieve and filter the MAC address table from a network switch."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vlan", type=int, help="Filter results by VLAN ID")
    parser.add_argument("--mac", help="Filter by MAC address (any common format)")
    parser.add_argument(
        "--type",
        choices=["DYNAMIC", "STATIC"],
        help="Filter by entry type",
    )
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Emit JSON instead of a human-readable table")
    parser.add_argument("--timeout", type=int, default=10,
                        help="SSH connection timeout in seconds (default: 10)")
    args = parser.parse_args()

    log.info("Connecting to %s:%s", args.device, args.port)
    client = ssh_connect(args.device, args.username, args.password, args.port, args.timeout)

    try:
        cmd = "show mac address-table"
        if args.vlan:
            cmd += f" vlan {args.vlan}"
        log.info("Running: %s", cmd)
        raw = run_command(client, cmd, timeout=args.timeout)
    finally:
        client.close()

    entries = parse_mac_table(raw)
    log.info("Parsed %d raw entries", len(entries))

    if args.vlan:
        entries = [e for e in entries if e["vlan"] == args.vlan]
    if args.mac:
        target = normalize_mac(args.mac)
        if not target:
            log.error("Unrecognized MAC address format: %s", args.mac)
            sys.exit(1)
        entries = [e for e in entries if e["mac"] == target]
    if args.type:
        entries = [e for e in entries if e["type"] == args.type]

    if args.as_json:
        print(json.dumps(entries, indent=2))
    else:
        print_table(entries)


if __name__ == "__main__":
    main()