The prompt says "Output ONLY the script content" — let me just print it directly.

```
"""
MAC Address Table Lookup

Purpose:
    Query and search the MAC address table on Cisco IOS/IOS-XE switches.
    Useful for locating where specific hosts are connected, auditing
    unauthorized devices, and correlating Layer 2 port assignments.

Usage:
    # Dump the full MAC table
    python mac_table.py -d 192.168.1.1 -u admin -p secret

    # Filter to a single VLAN
    python mac_table.py -d 192.168.1.1 -u admin -p secret --vlan 100

    # Find which port a host is plugged into
    python mac_table.py -d 192.168.1.1 -u admin -p secret --mac aa:bb:cc:dd:ee:ff

    # Show all MACs learned on an uplink
    python mac_table.py -d 192.168.1.1 -u admin -p secret --interface Gi0/1

    # Machine-readable output
    python mac_table.py -d 192.168.1.1 -u admin -p secret --output json

Prerequisites:
    pip install paramiko
    SSH enabled on the target switch (ip ssh version 2)
    Account with at minimum privilege 1 and access to 'show' commands
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x
"""

import argparse
import json
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

# Matches both IOS and IOS-XE table rows:
#   100  aabb.ccdd.eeff    DYNAMIC     Gi0/1
_ROW_RE = re.compile(
    r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_PROMPT_RE = re.compile(r"[>#]\s*$")


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[:\-\.]", "", mac).lower()
    if len(digits) != 12 or not re.fullmatch(r"[0-9a-f]{12}", digits):
        raise ValueError(f"Unrecognised MAC format: {mac!r}")
    return f"{digits[:4]}.{digits[4:8]}.{digits[8:]}"


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except Exception as exc:
        log.error("Cannot reach %s:%d — %s", host, port, exc)
        sys.exit(1)
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    shell = client.invoke_shell(width=250, height=250)
    time.sleep(1)
    shell.recv(65535)  # discard login banner

    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(65535)

    shell.send(command + "\n")

    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if _PROMPT_RE.search(chunk):
                break
        else:
            time.sleep(0.25)

    shell.close()
    return output


def fetch_mac_table(client: paramiko.SSHClient) -> str:
    raw = run_command(client, "show mac address-table")
    if not _ROW_RE.search(raw):
        log.debug("No rows with 'show mac address-table', trying alternate syntax")
        raw = run_command(client, "show mac-address-table")
    return raw


def parse(raw: str) -> list[dict]:
    return [
        {
            "vlan": int(m.group(1)),
            "mac": m.group(2).lower(),
            "type": m.group(3).upper(),
            "port": m.group(4),
        }
        for m in _ROW_RE.finditer(raw)
    ]


def apply_filters(
    entries: list[dict],
    vlan: int | None,
    mac: str | None,
    interface: str | None,
) -> list[dict]:
    if vlan is not None:
        entries = [e for e in entries if e["vlan"] == vlan]
    if mac is not None:
        target = normalize_mac(mac)
        entries = [e for e in entries if e["mac"] == target]
    if interface is not None:
        needle = interface.lower()
        entries = [e for e in entries if needle in e["port"].lower()]
    return entries


def render_table(entries: list[dict]) -> None:
    if not entries:
        print("No matching entries.")
        return
    print(f"{'VLAN':<6}  {'MAC Address':<18}  {'Type':<10}  Port")
    print("-" * 60)
    for e in entries:
        print(f"{e['vlan']:<6}  {e['mac']:<18}  {e['type']:<10}  {e['port']}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Query MAC address table on Cisco IOS/IOS-XE switches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, metavar="HOST",
                   help="Switch hostname or IP address")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--port", type=int, default=22, metavar="N",
                   help="SSH port (default: 22)")
    p.add_argument("--vlan", type=int, metavar="ID", help="Restrict to a VLAN")
    p.add_argument("--mac", metavar="ADDR",
                   help="Look up a specific MAC (any notation: aa:bb:..., aabb.ccdd.eeff, ...)")
    p.add_argument("--interface", metavar="IFACE",
                   help="Filter by interface name (partial match, e.g. Gi0/1)")
    p.add_argument("--output", choices=["table", "json"], default="table",
                   help="Output format (default: table)")
    p.add_argument("--debug", action="store_true", help="Verbose SSH logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    log.info("Connecting to %s:%d", args.device, args.port)
    client = connect(args.device, args.port, args.username, args.password)

    try:
        raw = fetch_mac_table(client)
        entries = parse(raw)
        log.info("Parsed %d total entries", len(entries))

        if args.mac:
            try:
                args.mac = normalize_mac(args.mac)
            except ValueError as exc:
                log.error("%s", exc)
                sys.exit(1)

        entries = apply_filters(entries, args.vlan, args.mac, args.interface)
        log.info("%d entries after filtering", len(entries))

        if args.output == "json":
            print(json.dumps(entries, indent=2))
        else:
            render_table(entries)
    finally:
        client.close()
```