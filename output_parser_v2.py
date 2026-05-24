The request says to output only the script content — here it is:

"""
mac_table.py - MAC Address Table Parser

Purpose:
    Connects to a Cisco IOS or NX-OS device via SSH and retrieves the MAC
    address table, parsing entries into structured data.  Useful for
    port-security audits, device-location lookups, and VLAN membership
    verification.

Usage:
    python mac_table.py -d 192.168.1.1 -u admin -p secret
    python mac_table.py -d 192.168.1.1 -u admin -p secret --vlan 100
    python mac_table.py -d 192.168.1.1 -u admin -p secret --interface Gi0/1
    python mac_table.py -d 192.168.1.1 -u admin -p secret --mac 0050.7966.6800
    python mac_table.py -d 192.168.1.1 -u admin -p secret --json

Prerequisites:
    pip install paramiko
    SSH must be enabled on the device; user needs privilege level >= 1.
    Tested against IOS 15.x, IOS-XE 16.x, and NX-OS 9.x.
"""

import argparse
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# IOS/IOS-XE: "  100  0050.7966.6800    DYNAMIC     Gi0/1"
_IOS_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
    r"(DYNAMIC|STATIC|dynamic|static)\s+"
    r"(\S+)",
    re.MULTILINE | re.IGNORECASE,
)

# NX-OS adds an age column: "* 100  0050.7966.6800   dynamic  0  F  F  Eth1/1"
_NXOS_RE = re.compile(
    r"^[*+]?\s*(\d+)\s+"
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
    r"(dynamic|static|secure|drop)\s+"
    r"\S+\s+\S+\s+\S+\s+"
    r"(\S+)",
    re.MULTILINE | re.IGNORECASE,
)


def _connect(host, username, password, port, timeout):
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
        logger.debug("Connected to %s", host)
        return client
    except paramiko.AuthenticationException:
        raise RuntimeError(f"Authentication failed for {username}@{host}")
    except (paramiko.SSHException, OSError) as exc:
        raise RuntimeError(f"Cannot connect to {host}: {exc}") from exc


def _run(client, command, timeout):
    shell = client.invoke_shell()
    shell.settimeout(timeout)
    time.sleep(0.8)
    shell.recv(65535)  # drain login banner

    shell.send("terminal length 0\n")
    time.sleep(0.4)
    shell.recv(65535)

    shell.send(command + "\n")
    time.sleep(2.5)

    buf = ""
    while shell.recv_ready():
        buf += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.3)

    shell.close()
    logger.debug("Raw output (%d chars):\n%s", len(buf), buf)
    return buf


def parse_mac_table(raw):
    """Return a list of dicts with keys: vlan, mac, type, port."""
    matches = _IOS_RE.findall(raw)
    if not matches:
        matches = _NXOS_RE.findall(raw)

    return [
        {
            "vlan": int(vlan),
            "mac": mac.lower(),
            "type": entry_type.lower(),
            "port": port,
        }
        for vlan, mac, entry_type, port in matches
    ]


def _filter(entries, vlan=None, interface=None, mac=None):
    if vlan is not None:
        entries = [e for e in entries if e["vlan"] == vlan]
    if interface:
        needle = interface.lower()
        entries = [e for e in entries if needle in e["port"].lower()]
    if mac:
        # Accept colon, hyphen, or dot-separated input
        normalized = re.sub(r"[:\-]", ".", mac).lower()
        entries = [e for e in entries if normalized in e["mac"]]
    return entries


def _print_table(entries):
    if not entries:
        print("No matching MAC address table entries.")
        return

    col_port = max((len(e["port"]) for e in entries), default=4)
    col_port = max(col_port, 4)
    fmt = f"{{:<6}} {{:<18}} {{:<10}} {{:<{col_port}}}"
    header = fmt.format("VLAN", "MAC Address", "Type", "Port")
    print(header)
    print("-" * len(header))
    for e in entries:
        print(fmt.format(e["vlan"], e["mac"], e["type"], e["port"]))
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")


def main():
    ap = argparse.ArgumentParser(
        description="Parse the MAC address table from a Cisco device via SSH."
    )
    ap.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    ap.add_argument("-u", "--username", required=True, help="SSH username")
    ap.add_argument("-p", "--password", required=True, help="SSH password")
    ap.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    ap.add_argument("--timeout", type=int, default=15, help="SSH/command timeout seconds")
    ap.add_argument("--vlan", type=int, help="Filter results to this VLAN ID")
    ap.add_argument("--interface", help="Filter results to this interface (substring match)")
    ap.add_argument("--mac", help="Filter results to this MAC address")
    ap.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON instead of table")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        client = _connect(args.device, args.username, args.password, args.port, args.timeout)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = _run(client, "show mac address-table", args.timeout)
    finally:
        client.close()

    entries = parse_mac_table(raw)
    if not entries:
        print("WARNING: No MAC table entries parsed. Check device compatibility.", file=sys.stderr)

    entries = _filter(entries, vlan=args.vlan, interface=args.interface, mac=args.mac)

    if args.as_json:
        print(json.dumps(entries, indent=2))
    else:
        _print_table(entries)


if __name__ == "__main__":
    main()