```python
"""
cdp_neighbor_map.py - Cisco CDP Neighbor Discovery and Topology Mapper

Purpose:
    Connects to one or more Cisco devices via SSH and parses 'show cdp neighbors
    detail' output into structured neighbor records. Useful for network topology
    documentation, undiscovered-device audits, and pre/post-change neighbor
    validation.

Usage:
    python cdp_neighbor_map.py -H 192.168.1.1 -u admin
    python cdp_neighbor_map.py -H 192.168.1.1 192.168.1.2 -u admin -p secret
    python cdp_neighbor_map.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa --json

Prerequisites:
    pip install paramiko
    CDP must be enabled on target Cisco IOS/IOS-XE/NX-OS devices.
    SSH access with a user that has at least privilege 1 (show commands).
"""

import argparse
import getpass
import json
import logging
import re
import time

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, settle=2.0):
    shell = client.invoke_shell()
    shell.settimeout(15)
    time.sleep(0.5)
    shell.recv(4096)
    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(4096)
    shell.send(f"{command}\n")
    time.sleep(settle)
    buf = []
    while shell.recv_ready():
        buf.append(shell.recv(32768).decode("utf-8", errors="replace"))
        time.sleep(0.2)
    shell.close()
    return "".join(buf)


def parse_cdp_detail(raw):
    neighbors = []
    for block in re.split(r"-{10,}", raw):
        if "Device ID" not in block:
            continue
        n = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\S+)", block)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"Platform:\s*([^,]+),\s*Capabilities:\s*(.+)", block)
        if m:
            n["platform"] = m.group(1).strip()
            n["capabilities"] = m.group(2).strip()
        m = re.search(r"Interface:\s*(\S+),\s+Port ID[^:]*:\s*(\S+)", block)
        if m:
            n["local_interface"] = m.group(1).rstrip(",")
            n["remote_interface"] = m.group(2)
        m = re.search(r"Holdtime\s*:\s*(\d+)", block)
        if m:
            n["holdtime"] = int(m.group(1))
        m = re.search(r"Version\s*:\s*(.*?)(?:\n\n|\Z)", block, re.DOTALL)
        if m:
            n["software_version"] = " ".join(m.group(1).split())[:120]
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def print_table(host, neighbors):
    print(f"\n=== CDP Neighbors for {host} ({len(neighbors)} found) ===")
    if not neighbors:
        print("  (none)")
        return
    fmt = "{:<28} {:<17} {:<16} {:<16} {}"
    header = fmt.format("Device ID", "IP Address", "Local Intf", "Remote Intf", "Platform/Capabilities")
    print(header)
    print("-" * min(len(header), 100))
    for n in neighbors:
        cap = n.get("platform", "") or n.get("capabilities", "N/A")
        print(fmt.format(
            n.get("device_id", "N/A")[:27],
            n.get("ip_address", "N/A")[:16],
            n.get("local_interface", "N/A")[:15],
            n.get("remote_interface", "N/A")[:15],
            cap[:40],
        ))


def main():
    parser = argparse.ArgumentParser(
        description="Map Cisco CDP neighbors via SSH.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-H", "--hosts", nargs="+", required=True, metavar="HOST",
                        help="One or more device IPs or hostnames")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None,
                        help="SSH password (prompted if omitted and no key given)")
    parser.add_argument("--key", dest="key_file", default=None, metavar="FILE",
                        help="Path to SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Emit structured JSON instead of a human-readable table")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug-level logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.key_file and args.password is None:
        args.password = getpass.getpass(f"SSH password for {args.username}: ")

    results = {}
    for host in args.hosts:
        log.info("Connecting to %s", host)
        try:
            client = ssh_connect(
                host=host,
                username=args.username,
                password=args.password,
                key_file=args.key_file,
                port=args.port,
                timeout=args.timeout,
            )
            raw = run_command(client, "show cdp neighbors detail")
            client.close()
            neighbors = parse_cdp_detail(raw)
            log.info("%s: %d neighbor(s) discovered", host, len(neighbors))
            results[host] = neighbors
            if not args.json_output:
                print_table(host, neighbors)
        except paramiko.AuthenticationException:
            log.error("Authentication failed: %s", host)
            results[host] = {"error": "authentication_failed"}
        except (paramiko.SSHException, OSError) as exc:
            log.error("Connection error on %s: %s", host, exc)
            results[host] = {"error": str(exc)}

    if args.json_output:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
```