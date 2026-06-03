```python
"""
mac_table_parser.py - Cisco MAC Address Table Parser

Connects to a Cisco IOS/IOS-XE/NX-OS device via SSH, retrieves the MAC address
table, and parses the output into structured records for filtering and export.
Useful for port-to-MAC mapping, rogue device detection, and inventory auditing.

Usage:
    python mac_table_parser.py -d 192.168.1.1 -u admin -p secret
    python mac_table_parser.py -d 192.168.1.1 -u admin --vlan 100
    python mac_table_parser.py -d 192.168.1.1 -u admin --interface Gi1/0/1
    python mac_table_parser.py -d 192.168.1.1 -u admin --output json
    python mac_table_parser.py -d 192.168.1.1 -u admin --output csv > macs.csv

Prerequisites:
    pip install paramiko
    Device must have SSH enabled; account requires at minimum 'show' privilege.
    Tested against IOS 15.x, IOS-XE 16.x/17.x, and NX-OS 9.x.
"""

import argparse
import csv
import getpass
import io
import json
import logging
import re
import sys
from typing import Optional

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

# IOS/IOS-XE: "VLAN  MAC  Type  Ports"
_IOS_RE = re.compile(
    r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)\s*$",
    re.IGNORECASE,
)
# NX-OS adds an "Age" column between Type and Port
_NXOS_RE = re.compile(
    r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+\S+\s+(\S+)\s*$",
    re.IGNORECASE,
)


def _ssh_exec(host: str, port: int, username: str, password: str, cmd: str) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        log.debug("Connected; running: %s", cmd)
        _, stdout, stderr = client.exec_command(cmd, timeout=30)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.warning("Device stderr: %s", err)
        return output
    finally:
        client.close()


def _normalize_mac(raw: str) -> str:
    """Collapse any MAC notation to XX:XX:XX:XX:XX:XX."""
    digits = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(digits) != 12:
        return raw.upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()


def parse_mac_table(raw: str) -> list:
    entries = []
    for line in raw.splitlines():
        m = _IOS_RE.match(line) or _NXOS_RE.match(line)
        if m:
            vlan, mac, entry_type, iface = m.groups()
            entries.append({
                "vlan": int(vlan),
                "mac": _normalize_mac(mac),
                "type": entry_type.lower(),
                "interface": iface,
            })
    return entries


def apply_filters(
    entries: list,
    vlan: Optional[int],
    interface: Optional[str],
    mac_prefix: Optional[str],
) -> list:
    if vlan is not None:
        entries = [e for e in entries if e["vlan"] == vlan]
    if interface:
        needle = interface.lower()
        entries = [e for e in entries if needle in e["interface"].lower()]
    if mac_prefix:
        prefix = _normalize_mac(mac_prefix).replace(":", "").lower()
        entries = [
            e for e in entries
            if e["mac"].replace(":", "").lower().startswith(prefix)
        ]
    return entries


def render_table(entries: list) -> str:
    if not entries:
        return "(no matching entries)"
    header = f"{'VLAN':<6}  {'MAC':<17}  {'TYPE':<10}  INTERFACE"
    sep = "-" * 55
    rows = [
        f"{e['vlan']:<6}  {e['mac']:<17}  {e['type']:<10}  {e['interface']}"
        for e in entries
    ]
    return "\n".join([header, sep] + rows + [sep, f"Total: {len(entries)} entries"])


def render_csv(entries: list) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["vlan", "mac", "type", "interface"])
    writer.writeheader()
    writer.writerows(entries)
    return buf.getvalue()


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Parse and filter the MAC address table from a Cisco device.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--vlan", type=int, default=None, help="Filter: show only this VLAN")
    p.add_argument("--interface", default=None, help="Filter: partial interface name match")
    p.add_argument("--mac-prefix", dest="mac_prefix", default=None,
                   help="Filter: OUI or MAC prefix (e.g. 00:1A:2B)")
    p.add_argument("--output", choices=["table", "json", "csv"], default="table",
                   help="Output format")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p


if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        raw = _ssh_exec(args.device, args.port, args.username, password,
                        "show mac address-table")
    except paramiko.AuthenticationException:
        log.error("Authentication failed")
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    entries = parse_mac_table(raw)
    log.info("Parsed %d total MAC entries", len(entries))

    entries = apply_filters(entries, args.vlan, args.interface, args.mac_prefix)
    log.info("%d entries after filtering", len(entries))

    if args.output == "json":
        print(json.dumps(entries, indent=2))
    elif args.output == "csv":
        print(render_csv(entries), end="")
    else:
        print(render_table(entries))
```