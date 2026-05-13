The user wants the raw script content printed to output. Here it is:

```
"""cdp_neighbors.py - CDP/LLDP Neighbor Discovery and Topology Mapper

Connects to a Cisco IOS/IOS-XE/NX-OS device via SSH and retrieves neighbor
discovery information using CDP or LLDP.  Parses the detail output into
structured records showing device IDs, management IPs, local/remote
interfaces, platform strings, and capabilities.  Results can be displayed
as a formatted topology table, serialized to JSON, or exported to CSV for
import into documentation tools.

Usage:
    python cdp_neighbors.py -d 10.0.0.1 -u admin -p secret
    python cdp_neighbors.py -d 10.0.0.1 -u admin --key ~/.ssh/id_rsa --lldp
    python cdp_neighbors.py -d 10.0.0.1 -u admin -p secret --json
    python cdp_neighbors.py -d 10.0.0.1 -u admin -p secret --csv neighbors.csv

Prerequisites:
    pip install paramiko
    CDP or LLDP must be globally enabled and running on the target device.
    The SSH user needs at minimum privilege level 1 (show command access).
"""

import argparse
import csv
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
)
log = logging.getLogger(__name__)

PROMPT_RE = re.compile(r"[#>]\s*$", re.MULTILINE)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_file),
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=30):
    """Open an interactive shell, disable paging, run command, return output."""
    shell = client.invoke_shell(width=220, height=50)
    shell.settimeout(timeout)

    def drain(wait=0.5):
        time.sleep(wait)
        buf = b""
        while shell.recv_ready():
            buf += shell.recv(65535)
        return buf.decode("utf-8", errors="replace")

    drain(1.0)  # eat login banner / MOTD
    shell.send("terminal length 0\n")
    drain(0.5)

    shell.send(command + "\n")
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if PROMPT_RE.search(chunk):
                break
        else:
            time.sleep(0.2)

    shell.close()
    # Strip the echoed command line and trailing prompt
    lines = output.splitlines()
    if lines and command.strip() in lines[0]:
        lines = lines[1:]
    while lines and PROMPT_RE.search(lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines)


def parse_cdp_detail(output):
    neighbors = []
    for block in re.split(r"-{5,}", output):
        if not block.strip():
            continue
        n = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1).rstrip(",")
        # Prefer the first management IP
        m = re.search(r"IP(?:v4)? address:\s*(\S+)", block, re.IGNORECASE)
        if not m:
            m = re.search(r"Entry address\(es\).*?IP(?:v4)? address:\s*(\S+)", block, re.DOTALL | re.IGNORECASE)
        n["ip_address"] = m.group(1) if m else ""
        m = re.search(r"Platform:\s*([^,]+)", block)
        n["platform"] = m.group(1).strip() if m else ""
        m = re.search(r"Capabilities:\s*(.+)", block)
        n["capabilities"] = m.group(1).strip() if m else ""
        m = re.search(r"Interface:\s*(\S+?)(?:,|$).*?Port ID.*?:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["local_interface"] = m.group(1)
            n["remote_interface"] = m.group(2)
        else:
            n["local_interface"] = ""
            n["remote_interface"] = ""
        if "device_id" in n:
            neighbors.append(n)
    return neighbors


def parse_lldp_detail(output):
    neighbors = []
    for block in re.split(r"-{5,}", output):
        if not block.strip():
            continue
        n = {}
        m = re.search(r"System Name:\s*(.+)", block)
        if m:
            n["device_id"] = m.group(1).strip()
        m = re.search(r"(?:Management Address|IP(?:v4)?)\s*[:\-]\s*(\d+\.\d+\.\d+\.\d+)", block, re.IGNORECASE)
        n["ip_address"] = m.group(1) if m else ""
        m = re.search(r"System Description:\s*(.+)", block)
        n["platform"] = m.group(1).strip() if m else ""
        m = re.search(r"System Capabilities:\s*(.+)", block)
        n["capabilities"] = m.group(1).strip() if m else ""
        m = re.search(r"Local Intf(?:erface)?:\s*(\S+)", block, re.IGNORECASE)
        n["local_interface"] = m.group(1) if m else ""
        m = re.search(r"Port (?:ID|id):\s*(\S+)", block)
        n["remote_interface"] = m.group(1) if m else ""
        if "device_id" in n:
            neighbors.append(n)
    return neighbors


def print_table(device, protocol, neighbors):
    print(f"\nNeighbor topology for {device}  [{protocol.upper()} detail]")
    print("=" * 90)
    if not neighbors:
        print("  No neighbors found.")
        return
    hdr = f"  {'Local Intf':<18} {'Neighbor Device':<28} {'Remote Intf':<18} {'Mgmt IP':<16} Capabilities"
    print(hdr)
    print(f"  {'-'*18} {'-'*28} {'-'*18} {'-'*16} {'-'*20}")
    for n in sorted(neighbors, key=lambda x: x.get("local_interface", "")):
        print(
            f"  {n.get('local_interface',''):<18}"
            f" {n.get('device_id',''):<28}"
            f" {n.get('remote_interface',''):<18}"
            f" {n.get('ip_address',''):<16}"
            f" {n.get('capabilities','')}"
        )
    print(f"\n  {len(neighbors)} neighbor(s) discovered.\n")


CSV_FIELDS = ["device_id", "ip_address", "local_interface", "remote_interface",
              "platform", "capabilities"]


def save_csv(path, neighbors):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(neighbors)
    log.info("Saved %d neighbors to %s", len(neighbors), path)


def main():
    parser = argparse.ArgumentParser(
        description="Discover CDP/LLDP neighbors and map local topology"
    )
    parser.add_argument("-d", "--device", required=True, metavar="HOST",
                        help="Device hostname or IP address")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_file", metavar="FILE",
                        help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--lldp", action="store_true",
                        help="Query LLDP instead of CDP")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="Print results as JSON")
    parser.add_argument("--csv", dest="csv_file", metavar="FILE",
                        help="Write results to CSV file")
    parser.add_argument("--timeout", type=int, default=30,
                        help="SSH/command timeout in seconds (default: 30)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    protocol = "lldp" if args.lldp else "cdp"
    command = f"show {protocol} neighbors detail"

    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = ssh_connect(
            args.device, args.username,
            password=args.password, key_file=args.key_file,
            port=args.port, timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("SSH connection error: %s", exc)
        sys.exit(1)

    try:
        log.info("Running: %s", command)
        raw = run_command(client, command, timeout=args.timeout)
        log.debug("Raw output (%d chars)", len(raw))
    except Exception as exc:
        log.error("Command failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    neighbors = parse_lldp_detail(raw) if args.lldp else parse_cdp_detail(raw)
    log.info("Parsed %d neighbor(s)", len(neighbors))

    if args.as_json:
        print(json.dumps(
            {"device": args.device, "protocol": protocol, "neighbors": neighbors},
            indent=2,
        ))
    else:
        print_table(args.device, protocol, neighbors)

    if args.csv_file:
        try:
            save_csv(args.csv_file, neighbors)
        except OSError as exc:
            log.error("CSV write failed: %s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()
```