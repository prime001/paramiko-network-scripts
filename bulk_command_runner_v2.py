```python
"""
mac_table.py - MAC Address Table Collector

Connects to one or more Cisco switches via SSH and retrieves the MAC address
table, producing a consolidated view of MAC-to-port mappings across the network.
Useful for locating devices, auditing port assignments, and detecting rogue MACs.

Usage:
    python mac_table.py -d 192.168.1.1 -u admin -p secret
    python mac_table.py -H switches.txt -u admin --key ~/.ssh/id_rsa
    python mac_table.py -d 10.0.0.1,10.0.0.2 -u cisco -p cisco --vlan 100 -o results.csv

Prerequisites:
    pip install paramiko
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_MAC_RE = re.compile(
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|"
    r"[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",
    re.IGNORECASE,
)


@dataclass
class MacEntry:
    device: str
    vlan: str
    mac: str
    mac_type: str
    port: str


def _ssh_connect(
    host: str,
    username: str,
    password: Optional[str],
    key_path: Optional[str],
    port: int,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, username=username, port=port, timeout=10)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _run(client: paramiko.SSHClient, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=15)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return out


def _parse(device: str, raw: str, vlan_filter: Optional[str]) -> List[MacEntry]:
    """Parse IOS/IOS-XE 'show mac address-table' output."""
    entries = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        vlan_col, mac_col, type_col, port_col = parts[0], parts[1], parts[2], parts[3]
        if not vlan_col.isdigit():
            continue
        if not _MAC_RE.match(mac_col):
            continue
        if vlan_filter and vlan_col != vlan_filter:
            continue
        entries.append(MacEntry(
            device=device,
            vlan=vlan_col,
            mac=mac_col.lower(),
            mac_type=type_col,
            port=port_col,
        ))
    return entries


def collect_device(
    host: str,
    username: str,
    password: Optional[str],
    key_path: Optional[str],
    port: int,
    vlan_filter: Optional[str],
) -> List[MacEntry]:
    try:
        client = _ssh_connect(host, username, password, key_path, port)
    except Exception as exc:
        log.error("SSH connect failed for %s: %s", host, exc)
        return []
    try:
        cmd = "show mac address-table"
        if vlan_filter:
            cmd += f" vlan {vlan_filter}"
        raw = _run(client, cmd)
        entries = _parse(host, raw, vlan_filter)
        log.info("%s: %d MAC entries collected", host, len(entries))
        return entries
    except Exception as exc:
        log.error("Command failed on %s: %s", host, exc)
        return []
    finally:
        client.close()


def _print_table(entries: List[MacEntry]) -> None:
    if not entries:
        print("No MAC entries found.")
        return
    fmt = "{:<18} {:>5} {:<20} {:<10} {}"
    print(fmt.format("Device", "VLAN", "MAC", "Type", "Port"))
    print("-" * 72)
    for e in entries:
        print(fmt.format(e.device, e.vlan, e.mac, e.mac_type, e.port))


def _write_csv(entries: List[MacEntry], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["device", "vlan", "mac", "type", "port"])
        for e in entries:
            writer.writerow([e.device, e.vlan, e.mac, e.mac_type, e.port])
    log.info("Results written to %s", path)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect MAC address tables from Cisco switches via SSH."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--devices", help="Comma-separated device IPs/hostnames")
    target.add_argument("-H", "--host-file", metavar="FILE", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    cred = parser.add_mutually_exclusive_group(required=True)
    cred.add_argument("-p", "--password", help="SSH password")
    cred.add_argument("--key", metavar="PATH", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vlan", help="Filter to a specific VLAN ID")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write results to CSV")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.devices:
        hosts = [h.strip() for h in args.devices.split(",") if h.strip()]
    else:
        try:
            with open(args.host_file) as fh:
                hosts = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as exc:
            log.error("Cannot read host file: %s", exc)
            sys.exit(1)

    if not hosts:
        log.error("No hosts to connect to.")
        sys.exit(1)

    all_entries: List[MacEntry] = []
    for host in hosts:
        all_entries.extend(
            collect_device(host, args.username, args.password, args.key, args.port, args.vlan)
        )

    _print_table(all_entries)

    if args.output:
        _write_csv(all_entries, args.output)

    log.info("Done — %d total entries from %d device(s).", len(all_entries), len(hosts))
```