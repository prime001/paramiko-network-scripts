```python
"""
interface_error_monitor.py - Audit interface error counters on Cisco IOS devices.

Purpose:
    Connects to a network device via SSH, retrieves full interface counters,
    and flags interfaces whose error counts exceed a configurable threshold.
    Useful for proactive fault detection: CRC spikes, input drops, and output
    queue discards often precede outages visible in plain up/down status.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python interface_error_monitor.py -H 192.168.1.1 -u admin --threshold 50 --output errors.json

Prerequisites:
    - Python 3.7+
    - paramiko: pip install paramiko
    - SSH access with at least read-only privileges
    - Cisco IOS / IOS-XE device (show interfaces output format)
"""

import argparse
import json
import logging
import re
import sys
import time
from getpass import getpass

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=30):
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


def run_command(shell, command, wait=2.0, buf=65535):
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(buf).decode("utf-8", errors="replace")
        time.sleep(0.2)
    return output


def parse_interface_errors(raw_output):
    """Parse 'show interfaces' and return per-interface error counter dicts."""
    interfaces = []
    current = None

    re_intf = re.compile(
        r"^(\S+)\s+is\s+(administratively down|up|down),\s+line protocol is\s+(up|down)"
    )
    re_input = re.compile(
        r"(\d+)\s+input errors,\s*(\d+)\s+CRC,\s*(\d+)\s+frame,\s*(\d+)\s+overrun"
    )
    re_output = re.compile(
        r"(\d+)\s+output errors,\s*(\d+)\s+collisions,\s*(\d+)\s+interface resets"
    )
    re_drops = re.compile(r"(\d+)\s+output drops")
    re_ignored = re.compile(r"(\d+)\s+ignored")

    for line in raw_output.splitlines():
        m = re_intf.match(line.strip())
        if m:
            if current:
                interfaces.append(current)
            admin_down = "administratively" in m.group(2)
            current = {
                "interface": m.group(1),
                "admin_status": "admin-down" if admin_down else m.group(2),
                "line_status": m.group(3),
                "input_errors": 0,
                "crc_errors": 0,
                "frame_errors": 0,
                "overruns": 0,
                "output_errors": 0,
                "collisions": 0,
                "resets": 0,
                "output_drops": 0,
                "ignored": 0,
            }
            continue

        if current is None:
            continue

        m = re_input.search(line)
        if m:
            current["input_errors"] = int(m.group(1))
            current["crc_errors"] = int(m.group(2))
            current["frame_errors"] = int(m.group(3))
            current["overruns"] = int(m.group(4))
            continue

        m = re_output.search(line)
        if m:
            current["output_errors"] = int(m.group(1))
            current["collisions"] = int(m.group(2))
            current["resets"] = int(m.group(3))
            continue

        m = re_drops.search(line)
        if m:
            current["output_drops"] = int(m.group(1))
            continue

        m = re_ignored.search(line)
        if m:
            current["ignored"] = int(m.group(1))

    if current:
        interfaces.append(current)

    return interfaces


def flag_problematic(interfaces, threshold):
    results = []
    for intf in interfaces:
        total = intf["input_errors"] + intf["output_errors"] + intf["output_drops"]
        if total >= threshold:
            results.append({**intf, "total_errors": total})
    return sorted(results, key=lambda x: x["total_errors"], reverse=True)


def print_report(flagged, threshold, total_count):
    print(f"\n{'=' * 72}")
    print(f"  Interface Error Counter Report  —  threshold: {threshold}")
    print(f"  Scanned {total_count} interfaces, {len(flagged)} flagged")
    print(f"{'=' * 72}")
    if not flagged:
        print("  All interfaces are within acceptable error limits.")
    else:
        hdr = f"  {'Interface':<26} {'Status':<14} {'In Err':>8} {'CRC':>8} {'Out Drop':>10}"
        print(hdr)
        print("  " + "-" * 68)
        for intf in flagged:
            status = f"{intf['admin_status']}/{intf['line_status']}"
            print(
                f"  {intf['interface']:<26} {status:<14} "
                f"{intf['input_errors']:>8} {intf['crc_errors']:>8} "
                f"{intf['output_drops']:>10}"
            )
    print(f"{'=' * 72}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Flag interfaces with elevated error counters on Cisco IOS devices."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--key", dest="key_file", default=None, help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--threshold", type=int, default=10,
        help="Total error count to flag an interface (default: 10)"
    )
    parser.add_argument("--output", default=None, help="Write JSON results to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    password = args.password
    if not password and not args.key_file:
        password = getpass(f"Password for {args.username}@{args.host}: ")

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = ssh_connect(
            args.host, args.username,
            password=password, key_file=args.key_file, port=args.port
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell(width=250, height=50)
        time.sleep(1)
        shell.recv(65535)  # drain login banner
        run_command(shell, "terminal length 0", wait=1)
        log.info("Collecting interface counters…")
        raw = run_command(shell, "show interfaces", wait=4)
    finally:
        client.close()

    interfaces = parse_interface_errors(raw)
    if not interfaces:
        log.error("No interfaces parsed — verify device type and SSH output format")
        sys.exit(1)

    log.info("Parsed %d interfaces", len(interfaces))
    flagged = flag_problematic(interfaces, args.threshold)
    print_report(flagged, args.threshold, len(interfaces))

    if args.output:
        payload = {
            "host": args.host,
            "threshold": args.threshold,
            "total_interfaces": len(interfaces),
            "flagged_count": len(flagged),
            "flagged": flagged,
            "all_interfaces": interfaces,
        }
        with open(args.output, "w") as fh:
            json.dump(payload, fh, indent=2)
        log.info("Full results written to %s", args.output)

    # Exit 2 when flagged interfaces found — useful for monitoring integrations
    sys.exit(2 if flagged else 0)


if __name__ == "__main__":
    main()
```