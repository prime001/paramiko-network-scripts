Interface Error Counter Monitor
================================
Connects to a network device via SSH and audits interface error counters,
flagging any interface whose input errors, output errors, CRC errors, or
input drops exceed configurable thresholds.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa \
        --crc-threshold 100 --error-threshold 50 --json

Prerequisites:
    pip install paramiko

Supported platforms: Cisco IOS / IOS-XE (show interfaces output format).
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
    level=logging.WARNING,
    format="%(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def _run_command(channel, command, timeout=15):
    channel.send(command + "\n")
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if re.search(r"[#>]\s*$", chunk):
                break
        time.sleep(0.1)
    return output


def connect(host, port, username, password=None, key_path=None, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        allow_agent=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password
        connect_kwargs["look_for_keys"] = False
    client.connect(**connect_kwargs)
    return client


def fetch_interface_counters(client):
    channel = client.invoke_shell(width=200, height=1000)
    time.sleep(1)
    channel.recv(65535)  # drain banner / prompt
    _run_command(channel, "terminal length 0")
    raw = _run_command(channel, "show interfaces", timeout=30)
    channel.close()
    return raw


def parse_counters(raw):
    """Return list of dicts with per-interface error counter summary."""
    interfaces = []
    current = {}

    for line in raw.splitlines():
        m = re.match(r"^(\S+(?:\s\S+)?)\s+is\s+(up|down|administratively down)", line)
        if m:
            if current:
                interfaces.append(current)
            current = {
                "name": m.group(1),
                "status": m.group(2),
                "input_errors": 0,
                "output_errors": 0,
                "crc": 0,
                "input_drops": 0,
                "output_drops": 0,
            }
            continue

        if not current:
            continue

        m = re.search(r"(\d+)\s+input errors", line)
        if m:
            current["input_errors"] = int(m.group(1))
        m = re.search(r"(\d+)\s+CRC", line)
        if m:
            current["crc"] = int(m.group(1))
        m = re.search(r"(\d+)\s+output errors", line)
        if m:
            current["output_errors"] = int(m.group(1))
        m = re.search(r"(\d+)\s+(?:input drops|no buffer)", line)
        if m:
            current["input_drops"] = int(m.group(1))
        m = re.search(r"(\d+)\s+output drops", line)
        if m:
            current["output_drops"] = int(m.group(1))

    if current:
        interfaces.append(current)

    return interfaces


def check_thresholds(interfaces, error_threshold, crc_threshold, drop_threshold):
    flagged = []
    for iface in interfaces:
        reasons = []
        if iface["input_errors"] >= error_threshold:
            reasons.append(f"input_errors={iface['input_errors']}")
        if iface["output_errors"] >= error_threshold:
            reasons.append(f"output_errors={iface['output_errors']}")
        if iface["crc"] >= crc_threshold:
            reasons.append(f"crc={iface['crc']}")
        if iface["input_drops"] >= drop_threshold:
            reasons.append(f"input_drops={iface['input_drops']}")
        if iface["output_drops"] >= drop_threshold:
            reasons.append(f"output_drops={iface['output_drops']}")
        if reasons:
            flagged.append({**iface, "violations": reasons})
    return flagged


def main():
    parser = argparse.ArgumentParser(
        description="Audit interface error counters on a Cisco IOS/IOS-XE device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--key", dest="key_path", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--error-threshold", type=int, default=10,
                        help="Flag when input/output errors >= N (default: 10)")
    parser.add_argument("--crc-threshold", type=int, default=10,
                        help="Flag when CRC errors >= N (default: 10)")
    parser.add_argument("--drop-threshold", type=int, default=100,
                        help="Flag when input/output drops >= N (default: 100)")
    parser.add_argument("--all", dest="show_all", action="store_true",
                        help="Print all interfaces, not just flagged ones")
    parser.add_argument("--json", dest="output_json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_path:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        log.debug("Connecting to %s:%d", args.device, args.port)
        client = connect(
            host=args.device,
            port=args.port,
            username=args.username,
            password=password,
            key_path=args.key_path,
        )
    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Could not connect to {args.device}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = fetch_interface_counters(client)
    finally:
        client.close()

    interfaces = parse_counters(raw)
    if not interfaces:
        print("WARNING: No interface data parsed. Check device output format.", file=sys.stderr)
        sys.exit(2)

    flagged = check_thresholds(
        interfaces,
        error_threshold=args.error_threshold,
        crc_threshold=args.crc_threshold,
        drop_threshold=args.drop_threshold,
    )

    display = interfaces if args.show_all else flagged

    if args.output_json:
        result = {
            "device": args.device,
            "total_interfaces": len(interfaces),
            "flagged_count": len(flagged),
            "thresholds": {
                "error": args.error_threshold,
                "crc": args.crc_threshold,
                "drop": args.drop_threshold,
            },
            "interfaces": display,
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"Device: {args.device}  |  Interfaces: {len(interfaces)}  |  Flagged: {len(flagged)}")
        print(f"Thresholds — errors: {args.error_threshold}  crc: {args.crc_threshold}  drops: {args.drop_threshold}")
        print()
        if not display:
            print("No interfaces exceed thresholds.")
            return
        col = "{:<30} {:<6} {:>12} {:>12} {:>8} {:>12} {:>12}"
        print(col.format("Interface", "Status", "In Errors", "Out Errors", "CRC", "In Drops", "Out Drops"))
        print("-" * 96)
        for iface in display:
            print(col.format(
                iface["name"][:29],
                iface["status"][:6],
                iface["input_errors"],
                iface["output_errors"],
                iface["crc"],
                iface["input_drops"],
                iface["output_drops"],
            ))

    if flagged:
        sys.exit(3)


if __name__ == "__main__":
    main()