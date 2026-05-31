```python
"""
vlan_table.py - Retrieve and parse VLAN table from Cisco IOS/NX-OS devices.

Purpose:
    SSH into a network device, run 'show vlan brief', and parse the output
    into structured data showing VLAN ID, name, status, and assigned ports.
    Useful for auditing VLAN assignments and identifying unused VLANs.

Usage:
    python vlan_table.py -d 192.168.1.1 -u admin -p secret
    python vlan_table.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python vlan_table.py -d 192.168.1.1 -u admin -p secret --status active --json

Prerequisites:
    pip install paramiko
    Device must allow SSH and 'show vlan brief' (Cisco IOS, IOS-XE, NX-OS)
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
logger = logging.getLogger(__name__)


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
        kwargs["look_for_keys"] = True
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.warning("stderr: %s", err.strip())
    return output


def parse_vlan_brief(output):
    """Parse IOS-style 'show vlan brief'; handles port continuation lines."""
    vlans = []
    data_started = False

    for line in output.splitlines():
        if re.match(r"^-{4,}", line):
            data_started = True
            continue
        if not data_started or not line.strip():
            continue

        match = re.match(
            r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|suspended|unsupported)\s*(.*)?$",
            line,
            re.IGNORECASE,
        )
        if match:
            vlan_id, name, status, ports_raw = match.groups()
            ports = [p.strip() for p in ports_raw.split(",") if p.strip()]
            vlans.append({"id": int(vlan_id), "name": name, "status": status.lower(), "ports": ports})
        elif vlans:
            additional = [p.strip() for p in line.strip().split(",") if p.strip()]
            if additional:
                vlans[-1]["ports"].extend(additional)

    return vlans


def format_table(vlans, device):
    if not vlans:
        return "No VLANs found."

    id_w = max(4, max(len(str(v["id"])) for v in vlans))
    name_w = max(16, max(len(v["name"]) for v in vlans))
    status_w = max(10, max(len(v["status"]) for v in vlans))

    header = f"{'VLAN':<{id_w}}  {'Name':<{name_w}}  {'Status':<{status_w}}  Ports"
    sep = "-" * len(header)
    lines = [f"\nVLAN Table — {device}", header, sep]

    for v in vlans:
        ports_str = ", ".join(v["ports"]) if v["ports"] else "(none)"
        lines.append(
            f"{v['id']:<{id_w}}  {v['name']:<{name_w}}  {v['status']:<{status_w}}  {ports_str}"
        )

    lines.append(f"\nTotal: {len(vlans)} VLAN(s)")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Parse VLAN table from Cisco IOS/NX-OS devices")
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", dest="key_file", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--status",
        choices=["active", "suspended", "all"],
        default="all",
        help="Filter VLANs by status (default: all)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.key_file and not args.password:
        args.password = getpass(f"Password for {args.username}@{args.device}: ")

    try:
        logger.info("Connecting to %s", args.device)
        client = ssh_connect(
            host=args.device,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        print(f"ERROR: Cannot connect to {args.device}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = run_command(client, "show vlan brief")
        logger.debug("Raw output:\n%s", raw)
    except Exception as exc:
        print(f"ERROR: Command execution failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

    vlans = parse_vlan_brief(raw)

    if args.status != "all":
        vlans = [v for v in vlans if args.status in v["status"]]

    if args.json:
        print(json.dumps(vlans, indent=2))
    else:
        print(format_table(vlans, args.device))


if __name__ == "__main__":
    main()
```