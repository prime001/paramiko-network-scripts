```python
#!/usr/bin/env python3
"""
cdp_lldp_neighbors.py - CDP/LLDP neighbor discovery via SSH

Purpose:
    Connect to a Cisco (or compatible) device over SSH and retrieve CDP and/or
    LLDP neighbor information. Parses neighbor detail output into structured
    data suitable for topology documentation or automated audits.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret --protocol lldp --json

Prerequisites:
    pip install paramiko
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username, timeout=15)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr for %r: %s", command, err)
    return out


def parse_cdp_detail(output):
    neighbors = []
    for block in re.split(r"-{10,}", output):
        block = block.strip()
        if not block:
            continue
        n = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"(?:IP address|IPv4 Address):\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["ip"] = m.group(1)
        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),", block)
        if m:
            n["local_port"] = m.group(1)
        m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)
        if m:
            n["remote_port"] = m.group(1)
        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def parse_lldp_detail(output):
    neighbors = []
    for block in re.split(r"\n{2,}", output.strip()):
        block = block.strip()
        if not block:
            continue
        n = {}
        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"Management Addresses[^\n]*\n\s+IP:\s*(\S+)", block)
        if not m:
            m = re.search(r"Management Address:\s*(\S+)", block)
        if m:
            n["ip"] = m.group(1)
        m = re.search(r"System Description:\s*\n\s+(.+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"(?:Local Intf|Interface):\s*(\S+)", block)
        if m:
            n["local_port"] = m.group(1)
        m = re.search(r"Port ID:\s*(\S+)", block)
        if m:
            n["remote_port"] = m.group(1)
        m = re.search(r"System Capabilities:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def print_table(device, protocol, neighbors):
    print(f"\n{protocol.upper()} neighbors — {device}")
    if not neighbors:
        print("  (none found)")
        return
    cols = ["device_id", "ip", "local_port", "remote_port", "platform"]
    widths = {c: max(len(c), max((len(n.get(c, "")) for n in neighbors), default=0))
              for c in cols}
    header = "  ".join(c.upper().ljust(widths[c]) for c in cols)
    rule = "  ".join("-" * widths[c] for c in cols)
    print(header)
    print(rule)
    for n in neighbors:
        print("  ".join(n.get(c, "").ljust(widths[c]) for c in cols))


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors on a network device via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Hostname or IP address")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_file", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp", "both"],
        default="both",
        help="Neighbor protocol to query (default: both)",
    )
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="Emit results as JSON")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        log.info("Connecting to %s", args.device)
        client = ssh_connect(args.device, args.username, args.password,
                             args.key_file, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    results = {}
    try:
        if args.protocol in ("cdp", "both"):
            log.info("Querying CDP neighbors")
            raw = run_command(client, "show cdp neighbors detail")
            results["cdp"] = parse_cdp_detail(raw)
            log.info("CDP: %d neighbor(s)", len(results["cdp"]))

        if args.protocol in ("lldp", "both"):
            log.info("Querying LLDP neighbors")
            raw = run_command(client, "show lldp neighbors detail")
            results["lldp"] = parse_lldp_detail(raw)
            log.info("LLDP: %d neighbor(s)", len(results["lldp"]))
    finally:
        client.close()

    if args.as_json:
        print(json.dumps(results, indent=2))
    else:
        for protocol, neighbors in results.items():
            print_table(args.device, protocol, neighbors)


if __name__ == "__main__":
    main()
```