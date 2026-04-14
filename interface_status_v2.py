"""
Interface Status Monitor
========================
Purpose:
    Connect to a network device via SSH and collect interface status information,
    including operational state, speed, duplex, description, and error counters.
    Outputs results as a formatted table or JSON for integration with other tools.

Usage:
    python interface_status.py -H 192.168.1.1 -u admin -p secret
    python interface_status.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python interface_status.py -H 192.168.1.1 -u admin -p secret --filter down
    python interface_status.py -H 192.168.1.1 -u admin -p secret --json

Prerequisites:
    pip install paramiko
    SSH access to target device (Cisco IOS/IOS-XE)
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.WARNING)
logger = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_path=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def run_command(client, command, timeout=30):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    if error.strip():
        logger.debug("stderr: %s", error.strip())
    return output


def parse_interface_status(raw_output):
    """Parse 'show interfaces status' or 'show ip interface brief' output."""
    interfaces = []
    # Try IOS 'show interfaces status' format first
    # Port      Name               Status       Vlan       Duplex  Speed Type
    status_pattern = re.compile(
        r"^(\S+)\s+(.*?)\s{2,}(connected|notconnect|disabled|err-disabled|sfpAbsent)\s+"
        r"(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$",
        re.MULTILINE,
    )
    matches = status_pattern.findall(raw_output)
    if matches:
        for m in matches:
            interfaces.append({
                "interface": m[0],
                "description": m[1].strip(),
                "status": m[2],
                "vlan": m[3],
                "duplex": m[4],
                "speed": m[5],
                "type": m[6],
            })
        return interfaces

    # Fallback: 'show ip interface brief'
    # Interface              IP-Address      OK? Method Status                Protocol
    brief_pattern = re.compile(
        r"^(\S+)\s+(\S+)\s+(YES|NO)\s+(\S+)\s+(up|down|administratively down)\s+(up|down)$",
        re.MULTILINE,
    )
    for m in brief_pattern.finditer(raw_output):
        interfaces.append({
            "interface": m.group(1),
            "ip_address": m.group(2),
            "ok": m.group(3),
            "method": m.group(4),
            "status": m.group(5).replace("administratively down", "admin-down"),
            "protocol": m.group(6),
        })
    return interfaces


def print_table(interfaces, filter_status=None):
    if filter_status:
        interfaces = [i for i in interfaces if filter_status.lower() in i["status"].lower()]

    if not interfaces:
        print("No interfaces match the specified filter.")
        return

    keys = list(interfaces[0].keys())
    col_widths = {k: max(len(k), max(len(str(row.get(k, ""))) for row in interfaces)) for k in keys}
    header = "  ".join(k.upper().ljust(col_widths[k]) for k in keys)
    separator = "  ".join("-" * col_widths[k] for k in keys)
    print(header)
    print(separator)
    for row in interfaces:
        line = "  ".join(str(row.get(k, "")).ljust(col_widths[k]) for k in keys)
        print(line)
    print(f"\nTotal: {len(interfaces)} interface(s)")


def main():
    parser = argparse.ArgumentParser(
        description="Collect and display interface status from a network device."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", metavar="KEY_FILE", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--filter",
        metavar="STATUS",
        help="Filter by status keyword, e.g. 'down', 'connected', 'err-disabled'",
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.key and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    logger.debug("Connecting to %s:%d", args.host, args.port)
    try:
        client = ssh_connect(
            host=args.host,
            username=args.username,
            password=args.password,
            key_path=args.key,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.host}", file=sys.stderr)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        print(f"ERROR: Could not connect to {args.host}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        logger.debug("Running 'show interfaces status'")
        raw = run_command(client, "show interfaces status")
        if not raw.strip() or "Invalid" in raw:
            logger.debug("Falling back to 'show ip interface brief'")
            raw = run_command(client, "show ip interface brief")
        interfaces = parse_interface_status(raw)
    except paramiko.SSHException as exc:
        print(f"ERROR: Command execution failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

    if not interfaces:
        print("WARNING: No interface data parsed. Raw output follows:\n")
        print(raw)
        sys.exit(1)

    if args.filter and args.json_output:
        interfaces = [i for i in interfaces if args.filter.lower() in i["status"].lower()]

    if args.json_output:
        print(json.dumps(interfaces, indent=2))
    else:
        print(f"\nInterface status for {args.host}\n")
        print_table(interfaces, filter_status=args.filter)


if __name__ == "__main__":
    main()