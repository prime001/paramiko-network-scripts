```python
"""
interface_status.py - Network Interface Status Monitor

Purpose:
    Connects to a network device via SSH and retrieves detailed interface
    status information including operational state, speed, duplex, errors,
    and utilization counters. Useful for quick triage and health checks.

Usage:
    python interface_status.py -d 192.168.1.1 -u admin -p secret
    python interface_status.py -d 192.168.1.1 -u admin --interface GigabitEthernet0/1
    python interface_status.py -d 192.168.1.1 -u admin --down-only --json
    python interface_status.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa

Prerequisites:
    pip install paramiko
    Target device must have SSH enabled and user must have privilege level
    sufficient to run 'show interfaces' (typically level 1 or higher).
    Tested against Cisco IOS/IOS-XE. Adjust parsing for other vendors.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_path=None, port=22, timeout=15):
    """Return an authenticated SSHClient or raise on failure."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password

    log.debug("Connecting to %s:%d as %s", host, port, username)
    client.connect(**connect_kwargs)
    return client


def run_command(client, command, timeout=30):
    """Execute a command and return stdout as a string."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stdin.close()
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr from device: %s", err)
    return output


def parse_interfaces(raw_output):
    """
    Parse 'show interfaces' output into a list of interface dicts.
    Handles Cisco IOS/IOS-XE format.
    """
    interfaces = []
    current = {}

    iface_re = re.compile(
        r"^(\S+)\s+is\s+(up|down|administratively down),\s+line protocol is\s+(up|down)"
    )
    desc_re = re.compile(r"^\s+Description:\s+(.+)$")
    hw_re = re.compile(r"^\s+Hardware is (.+?),\s+address is (\S+)")
    bw_re = re.compile(r"^\s+MTU (\d+) bytes, BW (\d+) Kbit")
    duplex_re = re.compile(r"^\s+(\S+[Dd]uplex),\s+(\S+),")
    errors_re = re.compile(
        r"^\s+(\d+) input errors.*?(\d+) output errors", re.DOTALL
    )
    input_re = re.compile(r"^\s+(\d+) packets input,\s+(\d+) bytes")
    output_p_re = re.compile(r"^\s+(\d+) packets output,\s+(\d+) bytes")

    for line in raw_output.splitlines():
        m = iface_re.match(line)
        if m:
            if current:
                interfaces.append(current)
            current = {
                "interface": m.group(1),
                "status": m.group(2),
                "protocol": m.group(3),
                "description": "",
                "hardware": "",
                "mac": "",
                "mtu": "",
                "bandwidth_kbit": "",
                "duplex": "",
                "speed": "",
                "input_packets": 0,
                "input_bytes": 0,
                "output_packets": 0,
                "output_bytes": 0,
                "input_errors": 0,
                "output_errors": 0,
            }
            continue

        if not current:
            continue

        m = desc_re.match(line)
        if m:
            current["description"] = m.group(1).strip()
            continue

        m = hw_re.match(line)
        if m:
            current["hardware"] = m.group(1).strip()
            current["mac"] = m.group(2)
            continue

        m = bw_re.match(line)
        if m:
            current["mtu"] = m.group(1)
            current["bandwidth_kbit"] = m.group(2)
            continue

        m = duplex_re.match(line)
        if m:
            current["duplex"] = m.group(1)
            current["speed"] = m.group(2)
            continue

        m = input_re.match(line)
        if m:
            current["input_packets"] = int(m.group(1))
            current["input_bytes"] = int(m.group(2))
            continue

        m = output_p_re.match(line)
        if m:
            current["output_packets"] = int(m.group(1))
            current["output_bytes"] = int(m.group(2))
            continue

        m = errors_re.match(line)
        if m:
            current["input_errors"] = int(m.group(1))
            current["output_errors"] = int(m.group(2))
            continue

    if current:
        interfaces.append(current)

    return interfaces


def format_table(interfaces):
    """Render interface list as a fixed-width table."""
    header = (
        f"{'Interface':<28} {'Status':<22} {'Protocol':<10} "
        f"{'Speed':<12} {'Duplex':<12} {'In Err':>8} {'Out Err':>8}  Description"
    )
    sep = "-" * len(header)
    rows = [header, sep]
    for i in interfaces:
        status_str = i["status"] if i["status"] != "administratively down" else "admin down"
        rows.append(
            f"{i['interface']:<28} {status_str:<22} {i['protocol']:<10} "
            f"{i['speed']:<12} {i['duplex']:<12} {i['input_errors']:>8} "
            f"{i['output_errors']:>8}  {i['description']}"
        )
    return "\n".join(rows)


def build_parser():
    p = argparse.ArgumentParser(
        description="Query interface status from a Cisco IOS/IOS-XE device via SSH."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("-k", "--key", dest="key_path", default=None, help="Path to SSH private key")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--interface", default=None, help="Filter to a specific interface name")
    p.add_argument("--down-only", action="store_true", help="Show only interfaces that are down")
    p.add_argument("--errors", action="store_true", help="Show only interfaces with input/output errors")
    p.add_argument("--json", action="store_true", dest="output_json", help="Output as JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_path:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = ssh_connect(
            host=args.device,
            username=args.username,
            password=password,
            key_path=args.key_path,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", args.device, exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Network error connecting to %s: %s", args.device, exc)
        sys.exit(1)

    try:
        command = "show interfaces"
        if args.interface:
            command = f"show interfaces {args.interface}"
        raw = run_command(client, command)
    finally:
        client.close()

    interfaces = parse_interfaces(raw)

    if not interfaces:
        print("No interface data parsed. Check device output format.", file=sys.stderr)
        sys.exit(1)

    if args.down_only:
        interfaces = [i for i in interfaces if i["protocol"] != "up"]
    if args.errors:
        interfaces = [i for i in interfaces if i["input_errors"] > 0 or i["output_errors"] > 0]

    if args.output_json:
        print(json.dumps(interfaces, indent=2))
    else:
        if not interfaces:
            print("No interfaces matched the specified filters.")
        else:
            print(f"\nDevice: {args.device}\n")
            print(format_table(interfaces))
            print(f"\nTotal: {len(interfaces)} interface(s) displayed.\n")


if __name__ == "__main__":
    main()
```