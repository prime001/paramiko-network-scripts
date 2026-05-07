Here is the complete script:

```python
"""
cdp_lldp_neighbors.py - Network Neighbor Discovery via CDP/LLDP

Connects to a network device via SSH using paramiko and queries CDP and/or
LLDP neighbor tables to map directly connected devices. Useful for building
network topology diagrams, auditing cabling, and verifying switch/router
adjacencies without relying on SNMP or NMS infrastructure.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --protocol lldp
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret --output json

Prerequisites:
    pip install paramiko
    SSH access to target device with sufficient privilege (show commands)
    CDP (Cisco) or LLDP must be enabled: `cdp run` / `lldp run`
"""

import argparse
import getpass
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


def connect(host, username, password, port=22, timeout=15):
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
    shell = client.invoke_shell(width=200, height=500)
    time.sleep(1.0)
    if shell.recv_ready():
        shell.recv(65535)
    _send(shell, "terminal length 0")
    return client, shell


def _send(shell, command, wait=1.5):
    shell.send(command + "\n")
    time.sleep(wait)
    buf = ""
    while shell.recv_ready():
        buf += shell.recv(65535).decode("utf-8", errors="replace")
    return buf


def parse_cdp(output):
    neighbors = []
    for block in re.split(r"-{10,}", output):
        if "Device ID" not in block:
            continue
        n = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"Platform:\s*([^,\n]+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+?),\s*Port ID[^:]*:\s*(\S+)", block)
        if m:
            n["local_intf"] = m.group(1)
            n["remote_intf"] = m.group(2)
        m = re.search(r"Version\s*:\s*\n?\s*(.+?)(?:\n|$)", block)
        if m:
            n["version"] = m.group(1).strip()
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def parse_lldp(output):
    neighbors = []
    for block in re.split(r"-{5,}", output):
        if "System Name" not in block and "Chassis id" not in block:
            continue
        n = {}
        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(
            r"Management Addresses?.*?(\d{1,3}(?:\.\d{1,3}){3})",
            block,
            re.DOTALL | re.IGNORECASE,
        )
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"System Description:\s*(.+?)(?:\n\s*\n|\Z)", block, re.DOTALL)
        if m:
            n["platform"] = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
        m = re.search(r"Local Intf(?:erface)?:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["local_intf"] = m.group(1)
        m = re.search(r"Port (?:id|ID):\s*(\S+)", block)
        if m:
            n["remote_intf"] = m.group(1)
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def print_table(neighbors, host, protocol):
    print(f"\n{protocol.upper()} neighbors on {host}")
    print("=" * 95)
    hdr = "{:<28} {:<16} {:<22} {:<22}"
    print(hdr.format("Device ID", "IP Address", "Local Interface", "Remote Interface"))
    print("-" * 95)
    for n in neighbors:
        print(hdr.format(
            n.get("device_id", "")[:27],
            n.get("ip_address", "N/A")[:15],
            n.get("local_intf", "N/A")[:21],
            n.get("remote_intf", "N/A")[:21],
        ))
    print(f"\nTotal: {len(neighbors)} neighbor(s)\n")


def build_parser():
    p = argparse.ArgumentParser(
        description="Discover directly connected neighbors via CDP or LLDP"
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--protocol",
        choices=["cdp", "lldp", "both"],
        default="cdp",
        help="Discovery protocol to query (default: cdp)",
    )
    p.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    p.add_argument("--timeout", type=int, default=15, help="SSH connect timeout in seconds")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main():
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    log.info("Connecting to %s", args.device)
    try:
        client, shell = connect(
            args.device, args.username, password, args.port, args.timeout
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("SSH connection failed: %s", exc)
        sys.exit(1)

    results = {}
    try:
        protocols = ["cdp", "lldp"] if args.protocol == "both" else [args.protocol]
        for proto in protocols:
            log.info("Querying %s neighbors", proto.upper())
            raw = _send(shell, f"show {proto} neighbors detail", wait=2.5)
            if "Invalid input" in raw or "% Error" in raw or "not enabled" in raw.lower():
                log.warning("%s not available on this device", proto.upper())
                continue
            neighbors = parse_cdp(raw) if proto == "cdp" else parse_lldp(raw)
            log.info("Found %d %s neighbor(s)", len(neighbors), proto.upper())
            results[proto] = neighbors
    finally:
        shell.close()
        client.close()

    if not results:
        log.warning("No neighbor data collected — verify CDP/LLDP is enabled")
        sys.exit(0)

    if args.output == "json":
        print(json.dumps(results, indent=2))
    else:
        for proto, neighbors in results.items():
            print_table(neighbors, args.device, proto)


if __name__ == "__main__":
    main()
```

**What this does differently from `device_inventory.py`:** Instead of inventorying *a single device*, it maps *connected neighbors* — parsing `show cdp/lldp neighbors detail` to extract device IDs, management IPs, platforms, and the local/remote interface pair for each link. The `--protocol both` flag queries both CDP and LLDP in one pass. Output is either a formatted table or JSON for downstream processing.