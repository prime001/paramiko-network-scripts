cdp_lldp_neighbors.py - Network Neighbor Discovery via CDP/LLDP

Purpose:
    Connects to a network device via SSH and retrieves CDP or LLDP neighbor
    information to map directly connected devices. Useful for building network
    topology maps and validating physical cabling without manual tracing.

Usage:
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --protocol lldp --json
    python cdp_lldp_neighbors.py -d 192.168.1.1 -u admin --timeout 30 -v

Prerequisites:
    - pip install paramiko
    - SSH access enabled on target device
    - CDP or LLDP enabled on target device (Cisco IOS/NX-OS/EOS)
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


def open_shell(host, username, password, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    channel = client.invoke_shell()
    channel.settimeout(timeout)
    time.sleep(1)
    channel.recv(4096)
    return client, channel


def send_command(channel, command, wait=2):
    channel.send(command + "\n")
    time.sleep(wait)
    output = ""
    while channel.recv_ready():
        output += channel.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.2)
    return output


def parse_cdp_neighbors(raw):
    neighbors = []
    for block in re.split(r"-{20,}", raw):
        if "Device ID" not in block:
            continue
        n = {}
        m = re.search(r"Device ID:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"IP address:\s*(\S+)", block)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),", block)
        if m:
            n["local_interface"] = m.group(1)
        m = re.search(r"Port ID.*?:\s*(\S+)", block)
        if m:
            n["remote_interface"] = m.group(1)
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def parse_lldp_neighbors(raw):
    neighbors = []
    for block in re.split(r"-{20,}", raw):
        if "System Name" not in block and "Chassis id" not in block:
            continue
        n = {}
        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", block)
        if m:
            n["ip_address"] = m.group(1)
        m = re.search(r"System Description[^:]*:\s*\n\s*(.+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"System Capabilities[^:]*:\s*\n\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        m = re.search(r"Local Interface:\s*(\S+)", block)
        if m:
            n["local_interface"] = m.group(1)
        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            n["remote_interface"] = m.group(1)
        if n.get("device_id") or n.get("ip_address"):
            neighbors.append(n)
    return neighbors


def print_table(neighbors, host, protocol):
    print(f"\n{protocol.upper()} neighbors on {host}:")
    header = f"{'Device ID':<32} {'Local Intf':<18} {'Remote Intf':<18} {'IP Address':<16} Platform"
    print(header)
    print("-" * len(header))
    for n in neighbors:
        print(
            f"{n.get('device_id', 'unknown'):<32}"
            f"{n.get('local_interface', 'unknown'):<18}"
            f"{n.get('remote_interface', 'unknown'):<18}"
            f"{n.get('ip_address', 'unknown'):<16}"
            f"{n.get('platform', 'unknown')}"
        )
    print(f"\nTotal: {len(neighbors)} neighbor(s)")


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors on a network device via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp"],
        default="cdp",
        help="Neighbor discovery protocol (default: cdp)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Emit JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    log.info("Connecting to %s", args.device)
    try:
        client, channel = open_shell(
            args.device, args.username, password,
            port=args.port, timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        send_command(channel, "terminal length 0", wait=1)

        command = f"show {args.protocol} neighbors detail"
        log.info("Running: %s", command)
        raw = send_command(channel, command, wait=3)
        log.debug("Raw output:\n%s", raw)

        neighbors = (
            parse_cdp_neighbors(raw) if args.protocol == "cdp"
            else parse_lldp_neighbors(raw)
        )

        if not neighbors:
            log.warning(
                "No %s neighbors found — verify %s is enabled on %s",
                args.protocol.upper(), args.protocol.upper(), args.device,
            )
            sys.exit(0)

        if args.json_output:
            print(json.dumps(
                {"device": args.device, "protocol": args.protocol, "neighbors": neighbors},
                indent=2,
            ))
        else:
            print_table(neighbors, args.device, args.protocol)
    finally:
        client.close()


if __name__ == "__main__":
    main()