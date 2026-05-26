The script is ready — here's the content (output only, no fences):

---

```
"""
interface_error_monitor.py - Network Interface Error Counter Monitor

Purpose:
    Connects to a network device via SSH and retrieves interface error
    statistics (CRC errors, input errors, output drops, interface resets).
    Flags interfaces exceeding a configurable threshold, useful for proactive
    fault detection before links fail completely.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret --threshold 50 --json

Prerequisites:
    pip install paramiko
    Target device must support "show interfaces" (Cisco IOS/IOS-XE/NX-OS).
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

_IFACE_HEADER = re.compile(
    r"^(\S+)\s+is\s+(up|down|administratively down)", re.MULTILINE
)
_INPUT_ERRORS = re.compile(r"(\d+)\s+input errors")
_CRC_ERRORS = re.compile(r"(\d+)\s+input errors.*?(\d+)\s+CRC", re.DOTALL)
_OUTPUT_DROPS = re.compile(r"(\d+)\s+output drops")
_RESETS = re.compile(r"(\d+)\s+interface resets")


def connect(host, port, username, password=None, key_file=None, timeout=30):
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
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide either --password or --key")
    client.connect(**kwargs)
    return client


def run_command(client, command, wait=3.0):
    shell = client.invoke_shell()
    shell.settimeout(15)
    time.sleep(0.5)
    if shell.recv_ready():
        shell.recv(4096)
    shell.send("terminal length 0\n")
    time.sleep(0.5)
    if shell.recv_ready():
        shell.recv(4096)
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
        time.sleep(0.2)
    shell.close()
    return output


def parse_error_counters(raw):
    blocks = re.split(r"\n(?=\S+\s+is\s+(?:up|down|administratively down))", raw)
    results = []
    for block in blocks:
        m = _IFACE_HEADER.match(block)
        if not m:
            continue
        name, state = m.group(1), m.group(2)

        input_errors = 0
        ie_m = _INPUT_ERRORS.search(block)
        if ie_m:
            input_errors = int(ie_m.group(1))
        crc = 0
        crc_m = _CRC_ERRORS.search(block)
        if crc_m:
            input_errors = int(crc_m.group(1))
            crc = int(crc_m.group(2))
        drops_m = _OUTPUT_DROPS.search(block)
        output_drops = int(drops_m.group(1)) if drops_m else 0
        reset_m = _RESETS.search(block)
        resets = int(reset_m.group(1)) if reset_m else 0

        results.append({
            "interface": name,
            "state": state,
            "input_errors": input_errors,
            "crc_errors": crc,
            "output_drops": output_drops,
            "resets": resets,
        })
    return results


def exceeds_threshold(iface, threshold):
    return any(
        iface[k] >= threshold
        for k in ("input_errors", "crc_errors", "output_drops", "resets")
    )


def print_table(interfaces, threshold):
    hdr = f"{'Interface':<32} {'State':<24} {'InErr':>7} {'CRC':>7} {'OutDrop':>8} {'Resets':>7}"
    print(hdr)
    print("-" * len(hdr))
    for iface in interfaces:
        flag = " !" if exceeds_threshold(iface, threshold) else ""
        print(
            f"{iface['interface']:<32} {iface['state']:<24}"
            f" {iface['input_errors']:>7} {iface['crc_errors']:>7}"
            f" {iface['output_drops']:>8} {iface['resets']:>7}{flag}"
        )


def build_parser():
    p = argparse.ArgumentParser(description="Report interface error counters on a network device")
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("--key", dest="key_file", default=None, help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--threshold", type=int, default=10,
        help="Error count that flags an interface (default: 10)",
    )
    p.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON instead of table")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if not args.key_file and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    logger.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = connect(
            host=args.device,
            port=args.port,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        logger.info("Running 'show interfaces'...")
        raw = run_command(client, "show interfaces", wait=3.0)
    finally:
        client.close()

    interfaces = parse_error_counters(raw)
    if not interfaces:
        logger.error("No interface data parsed — verify device output format")
        sys.exit(1)

    if args.as_json:
        print(json.dumps(interfaces, indent=2))
        sys.exit(0)

    flagged = [i for i in interfaces if exceeds_threshold(i, args.threshold)]
    print(f"\nInterface Error Report — {args.device}")
    print(f"Threshold: {args.threshold}  |  Total interfaces: {len(interfaces)}  |  Flagged: {len(flagged)}\n")
    print_table(interfaces, args.threshold)

    if flagged:
        print(f"\nFlagged ({len(flagged)}):")
        for iface in flagged:
            issues = ", ".join(
                f"{label}={iface[key]}"
                for label, key in [
                    ("CRC", "crc_errors"),
                    ("InErr", "input_errors"),
                    ("OutDrop", "output_drops"),
                    ("Resets", "resets"),
                ]
                if iface[key] >= args.threshold
            )
            print(f"  {iface['interface']} [{iface['state']}]: {issues}")
    else:
        print("\nNo interfaces exceeded the error threshold.")
```