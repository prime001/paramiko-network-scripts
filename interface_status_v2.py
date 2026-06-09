The write tool needs permission. Here is the complete script — output only, as requested:

```python
"""
Interface Error Monitor - Cisco IOS/IOS-XE

Connects to a network device via SSH and reports interface error counters
(input errors, output drops, CRC errors, giants, runts). Flags any interface
whose counters exceed user-defined thresholds, making it easy to spot degraded
links without scrolling through hundreds of show-interface lines.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \
        --crc-threshold 10 --error-threshold 50 --json

Prerequisites:
    pip install paramiko
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
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

_RE_IFACE = re.compile(r"^(\S+) is (up|down|administratively down)", re.MULTILINE)
_RE_INPUT_ERR = re.compile(r"(\d+) input errors")
_RE_CRC = re.compile(r"(\d+) CRC")
_RE_GIANTS = re.compile(r"(\d+) giants")
_RE_RUNTS = re.compile(r"(\d+) runts")
_RE_OUTPUT_DROP = re.compile(r"(\d+) output drops")
_RE_OUTPUT_ERR = re.compile(r"(\d+) output errors")


def ssh_exec(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr from device: %s", err)
    return output


def _int(match):
    return int(match.group(1)) if match else 0


def parse_interface_errors(raw):
    blocks = re.split(r"(?=^\S+\s+is (?:up|down|administratively down))", raw, flags=re.MULTILINE)
    results = []
    for block in blocks:
        m = _RE_IFACE.search(block)
        if not m:
            continue
        results.append({
            "interface": m.group(1),
            "status": m.group(2),
            "input_errors": _int(_RE_INPUT_ERR.search(block)),
            "crc": _int(_RE_CRC.search(block)),
            "giants": _int(_RE_GIANTS.search(block)),
            "runts": _int(_RE_RUNTS.search(block)),
            "output_drops": _int(_RE_OUTPUT_DROP.search(block)),
            "output_errors": _int(_RE_OUTPUT_ERR.search(block)),
        })
    return results


def check_thresholds(interfaces, args):
    flagged = []
    for iface in interfaces:
        reasons = []
        if iface["crc"] >= args.crc_threshold:
            reasons.append("CRC={}".format(iface["crc"]))
        if iface["input_errors"] >= args.error_threshold:
            reasons.append("input_errors={}".format(iface["input_errors"]))
        if iface["output_drops"] >= args.drop_threshold:
            reasons.append("output_drops={}".format(iface["output_drops"]))
        if iface["output_errors"] >= args.error_threshold:
            reasons.append("output_errors={}".format(iface["output_errors"]))
        if reasons:
            flagged.append(dict(iface, reasons=reasons))
    return flagged


def connect(args):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": args.device,
        "port": args.port,
        "username": args.username,
        "password": args.password,
        "timeout": args.timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if args.key:
        connect_kwargs["key_filename"] = args.key
        del connect_kwargs["password"]
    client.connect(**connect_kwargs)
    return client


def report_text(interfaces, flagged):
    print("\nScanned {} interface(s). {} flagged.\n".format(len(interfaces), len(flagged)))
    if not flagged:
        print("No interfaces exceeded thresholds.")
        return
    header = "{:<30} {:<20} {}".format("Interface", "Status", "Reason")
    print(header)
    print("-" * len(header))
    for iface in flagged:
        print("{:<30} {:<20} {}".format(
            iface["interface"], iface["status"], ", ".join(iface["reasons"])
        ))


def build_arg_parser():
    p = argparse.ArgumentParser(description="Monitor interface error counters on Cisco IOS devices.")
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("-k", "--key", default=None, help="Path to SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="SSH connection timeout in seconds")
    p.add_argument("--crc-threshold", type=int, default=5, dest="crc_threshold",
                   help="Flag interfaces with CRC errors >= this value (default: 5)")
    p.add_argument("--error-threshold", type=int, default=10, dest="error_threshold",
                   help="Flag interfaces with input/output errors >= this value (default: 10)")
    p.add_argument("--drop-threshold", type=int, default=100, dest="drop_threshold",
                   help="Flag interfaces with output drops >= this value (default: 100)")
    p.add_argument("--json", action="store_true", help="Output results as JSON")
    p.add_argument("--all", action="store_true", dest="show_all",
                   help="Show all interfaces, not just flagged ones")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key:
        args.password = getpass.getpass("Password for {}@{}: ".format(args.username, args.device))

    try:
        client = connect(args)
    except paramiko.AuthenticationException:
        print("ERROR: Authentication failed for {}@{}".format(args.username, args.device),
              file=sys.stderr)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        print("ERROR: Could not connect to {}: {}".format(args.device, exc), file=sys.stderr)
        sys.exit(1)

    try:
        raw = ssh_exec(client, "show interfaces")
    except paramiko.SSHException as exc:
        print("ERROR: Command execution failed: {}".format(exc), file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

    interfaces = parse_interface_errors(raw)
    if not interfaces:
        print(
            "ERROR: No interface data parsed. Verify the device is running Cisco IOS/IOS-XE.",
            file=sys.stderr,
        )
        sys.exit(1)

    flagged = check_thresholds(interfaces, args)
    display = interfaces if args.show_all else flagged

    if args.json:
        payload = {
            "device": args.device,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_interfaces": len(interfaces),
            "flagged_count": len(flagged),
            "interfaces": display,
        }
        print(json.dumps(payload, indent=2))
    else:
        report_text(interfaces, flagged)
```

This is `interface_error_monitor.py` — a threshold-based interface error counter inspector. It runs `show interfaces`, parses CRC/input-error/output-drop/runt/giant counters per interface, and reports only the ones that breach your thresholds. Distinct from the existing `interface_status*.py` scripts (which cover up/down/speed/duplex) — this targets link quality diagnostics. Supports `--json` for pipeline integration and `--all` to dump every interface's counters.