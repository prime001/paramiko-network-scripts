Here's the complete script — you can save it as `mac_table.py`:

```python
"""mac_table.py - MAC Address Table Collector and Parser

Purpose:
    Connects to a Cisco IOS/IOS-XE device via SSH, retrieves the MAC address
    table, and parses it into structured data. Supports filtering by VLAN,
    interface prefix, or entry type (DYNAMIC/STATIC) and outputs as a
    formatted table or JSON.

Usage:
    python mac_table.py -H 192.168.1.1 -u admin -p secret
    python mac_table.py -H 192.168.1.1 -u admin -p secret --vlan 100
    python mac_table.py -H 192.168.1.1 -u admin -p secret --interface Gi0/1
    python mac_table.py -H 192.168.1.1 -u admin -p secret --type DYNAMIC --json

Prerequisites:
    pip install paramiko
"""

import argparse
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def connect(host, port, username, password, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client, command, read_timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=read_timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.debug("stderr: %s", err.strip())
    return output


def parse_mac_table(output):
    entries = []
    # Matches Cisco IOS lines:  100  aabb.cc00.0100  DYNAMIC  Gi0/1
    pattern = re.compile(
        r"^\s*(\d+|All)\s+"
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(\S+)\s+"
        r"(\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        entries.append({
            "vlan": match.group(1),
            "mac": match.group(2).lower(),
            "type": match.group(3).upper(),
            "interface": match.group(4),
        })
    return entries


def filter_entries(entries, vlan=None, interface=None, entry_type=None):
    if vlan is not None:
        entries = [e for e in entries if e["vlan"] == str(vlan)]
    if interface:
        prefix = interface.lower()
        entries = [e for e in entries if e["interface"].lower().startswith(prefix)]
    if entry_type:
        entries = [e for e in entries if e["type"] == entry_type.upper()]
    return entries


def print_table(entries):
    if not entries:
        print("No matching MAC address table entries.")
        return
    col_iface = max(len(e["interface"]) for e in entries)
    col_iface = max(col_iface, 9)
    header = f"{'VLAN':<6}  {'MAC Address':<17}  {'Type':<10}  {'Interface':<{col_iface}}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(
            f"{e['vlan']:<6}  {e['mac']:<17}  {e['type']:<10}  {e['interface']:<{col_iface}}"
        )
    print(f"\nTotal: {len(entries)} entries")


def build_parser():
    p = argparse.ArgumentParser(
        description="Retrieve and parse the MAC address table from a network device."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--vlan", help="Filter results to a specific VLAN ID")
    p.add_argument("--interface", help="Filter by interface name prefix (e.g. Gi0/1)")
    p.add_argument(
        "--type",
        dest="entry_type",
        choices=["DYNAMIC", "STATIC"],
        help="Filter by entry type",
    )
    p.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")
    p.add_argument("--timeout", type=int, default=10, help="SSH connect timeout (seconds)")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main():
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    try:
        logger.info("Connecting to %s:%d", args.host, args.port)
        client = connect(args.host, args.port, args.username, args.password, args.timeout)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        logger.info("Fetching MAC address table from %s", args.host)
        output = run_command(client, "show mac address-table")
        if "Invalid input" in output or "% Unknown" in output:
            logger.debug("Retrying with alternate command syntax")
            output = run_command(client, "show mac-address-table")
    finally:
        client.close()

    entries = parse_mac_table(output)
    if not entries:
        logger.warning(
            "No entries parsed — output may not match expected format. "
            "Re-run with --debug to see raw output."
        )
        if args.debug:
            print(output)
        sys.exit(1)

    logger.info("Parsed %d total entries", len(entries))
    entries = filter_entries(entries, args.vlan, args.interface, args.entry_type)

    if args.as_json:
        print(json.dumps(entries, indent=2))
    else:
        print_table(entries)


if __name__ == "__main__":
    main()
```

**What this does:** Retrieves `show mac address-table` output via paramiko, parses each entry with a regex (VLAN / MAC / type / interface columns), then lets you filter by VLAN, interface prefix, or entry type (DYNAMIC/STATIC). Falls back to the hyphenated command syntax if the first fails. Output is either a formatted column table or JSON. ~160 lines, no overlap with the existing scripts.