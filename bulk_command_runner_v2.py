```python
"""
mac_table.py — MAC Address Table Collector

Purpose:
    Retrieves and displays the MAC address table from a Cisco IOS/IOS-XE switch
    via SSH. Useful for locating endpoints by MAC address, auditing port
    assignments, and mapping Layer-2 topology without SNMP access.

Usage:
    python mac_table.py -H 192.168.1.1 -u admin
    python mac_table.py -H 10.0.0.1 -u admin -p secret --vlan 100
    python mac_table.py -H 10.0.0.1 -u admin --mac 00:1a:2b --format json

Prerequisites:
    - Python 3.9+
    - paramiko >= 2.9.0  (pip install paramiko)
    - SSH enabled on target device with privilege to run 'show mac address-table'
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass
from typing import Optional

import paramiko

LOG = logging.getLogger(__name__)


@dataclass
class MACEntry:
    vlan: str
    mac: str
    mac_type: str
    port: str


def _ssh_connect(
    host: str, port: int, username: str, password: str, timeout: int
) -> paramiko.SSHClient:
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
    except paramiko.AuthenticationException:
        LOG.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as exc:
        LOG.error("SSH negotiation failed for %s: %s", host, exc)
        raise
    except OSError as exc:
        LOG.error("Cannot reach %s:%d — %s", host, port, exc)
        raise
    return client


def _run_command(client: paramiko.SSHClient, command: str) -> str:
    channel = client.invoke_shell()
    channel.settimeout(10.0)
    time.sleep(0.5)
    channel.recv(4096)  # discard banner/MOTD

    channel.send("terminal length 0\n")
    time.sleep(0.5)
    channel.recv(4096)

    channel.send(command + "\n")
    time.sleep(2.0)

    output = ""
    while channel.recv_ready():
        output += channel.recv(65536).decode("utf-8", errors="replace")
        time.sleep(0.2)

    channel.close()
    return output


def parse_mac_table(raw: str) -> list[MACEntry]:
    # Matches Cisco IOS/IOS-XE format:
    #   10    0050.56ab.cdef    DYNAMIC     GigabitEthernet0/1
    pattern = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(\S+)\s+"
        r"(\S+)\s*$",
        re.MULTILINE,
    )
    return [
        MACEntry(
            vlan=m.group(1),
            mac=m.group(2).lower(),
            mac_type=m.group(3),
            port=m.group(4),
        )
        for m in pattern.finditer(raw)
    ]


def filter_entries(
    entries: list[MACEntry],
    vlan: Optional[str],
    mac_prefix: Optional[str],
) -> list[MACEntry]:
    if vlan:
        entries = [e for e in entries if e.vlan == vlan]
    if mac_prefix:
        # normalise separators so 00:1a:2b, 00-1a-2b, 0050.56 all work
        prefix = mac_prefix.lower().replace(":", ".").replace("-", ".")
        entries = [e for e in entries if e.mac.startswith(prefix)]
    return entries


def print_table(entries: list[MACEntry]) -> None:
    if not entries:
        print("No MAC entries matched.")
        return
    col_widths = (6, 18, 10, 0)
    header = (
        f"{'VLAN':<{col_widths[0]}} "
        f"{'MAC Address':<{col_widths[1]}} "
        f"{'Type':<{col_widths[2]}} "
        f"Port"
    )
    print(header)
    print("-" * max(60, len(header)))
    for e in entries:
        print(
            f"{e.vlan:<{col_widths[0]}} "
            f"{e.mac:<{col_widths[1]}} "
            f"{e.mac_type:<{col_widths[2]}} "
            f"{e.port}"
        )
    print(f"\n{len(entries)} entries.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Retrieve the MAC address table from a Cisco switch via SSH."
    )
    parser.add_argument("-H", "--host", required=True, help="Switch IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vlan", help="Filter output to a specific VLAN ID")
    parser.add_argument(
        "--mac", help="Filter by MAC prefix, any separator (e.g. 00:1a:2b)"
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--timeout", type=int, default=15, help="SSH connect timeout in seconds"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    try:
        client = _ssh_connect(args.host, args.port, args.username, password, args.timeout)
    except Exception:
        return 1

    try:
        raw = _run_command(client, "show mac address-table")
    except Exception as exc:
        LOG.error("Command failed: %s", exc)
        return 1
    finally:
        client.close()

    entries = parse_mac_table(raw)
    if not entries:
        print(
            "No MAC entries parsed. Use --debug to inspect raw output.",
            file=sys.stderr,
        )
        if args.debug:
            print(raw)
        return 1

    entries = filter_entries(entries, args.vlan, args.mac)

    if args.format == "json":
        print(json.dumps([asdict(e) for e in entries], indent=2))
    else:
        print_table(entries)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```