The brainstorming skill applies to feature design work with the user, but here the spec is fully defined — the user wants script output only, no dialogue. Writing directly.

```python
"""
interface_error_monitor.py - Monitor interface error counters on network devices.

Purpose:
    Connects to a Cisco IOS/IOS-XE device via SSH and collects per-interface
    error counters (input errors, CRC, output drops, interface resets). Flags
    any interface where a counter meets or exceeds a configurable threshold and
    prints a formatted summary. Useful for proactive fault detection before
    errors cause service impact.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \\
        --threshold 50 --output errors.json

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device. The account needs privilege
    sufficient to run 'show interfaces'.
"""

import argparse
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

COMMAND = "show interfaces"
RECV_TIMEOUT = 15
BUFFER_SIZE = 65535

RE_IFACE = re.compile(r"^(\S+)\s+is\s+(up|down|administratively down)", re.MULTILINE)
RE_INPUT_ERRORS = re.compile(r"(\d+) input errors")
RE_CRC = re.compile(r"(\d+) CRC")
RE_OUTPUT_DROPS = re.compile(r"(\d+) output drops")
RE_RESETS = re.compile(r"(\d+) interface resets")
RE_RUNTS = re.compile(r"(\d+) runts")
RE_GIANTS = re.compile(r"(\d+) giants")


def ssh_connect(host: str, username: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        log.info("Connected to %s", host)
        return client
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection to %s failed: %s", host, exc)
        sys.exit(1)


def run_command(client: paramiko.SSHClient, command: str) -> str:
    channel = client.invoke_shell()
    channel.settimeout(RECV_TIMEOUT)
    time.sleep(1)
    channel.recv(BUFFER_SIZE)  # flush login banner

    channel.send("terminal length 0\n")
    time.sleep(0.5)
    channel.recv(BUFFER_SIZE)

    channel.send(f"{command}\n")

    output = b""
    deadline = time.time() + RECV_TIMEOUT
    while time.time() < deadline:
        if channel.recv_ready():
            output += channel.recv(BUFFER_SIZE)
            if output.rstrip().endswith(b"#"):
                break
        else:
            time.sleep(0.2)

    channel.close()
    return output.decode("utf-8", errors="replace")


def _extract(pattern: re.Pattern, text: str) -> int:
    m = pattern.search(text)
    return int(m.group(1)) if m else 0


def parse_interfaces(raw: str) -> list[dict]:
    blocks = re.split(r"(?=^\S+\s+is\s+(?:up|down|administratively down))", raw, flags=re.MULTILINE)
    results = []
    for block in blocks:
        m = RE_IFACE.search(block)
        if not m:
            continue
        results.append(
            {
                "interface": m.group(1),
                "status": m.group(2),
                "input_errors": _extract(RE_INPUT_ERRORS, block),
                "crc_errors": _extract(RE_CRC, block),
                "output_drops": _extract(RE_OUTPUT_DROPS, block),
                "resets": _extract(RE_RESETS, block),
                "runts": _extract(RE_RUNTS, block),
                "giants": _extract(RE_GIANTS, block),
            }
        )
    return results


def worst_counter(iface: dict) -> int:
    return max(
        iface["input_errors"],
        iface["crc_errors"],
        iface["output_drops"],
        iface["resets"],
        iface["runts"],
        iface["giants"],
    )


def print_report(interfaces: list[dict], threshold: int, host: str) -> int:
    flagged = [i for i in interfaces if worst_counter(i) >= threshold]

    print(f"\nInterface Error Report  —  {host}")
    print(f"Threshold : {threshold:,}   |   Interfaces polled : {len(interfaces)}")
    print(f"Flagged   : {len(flagged)}\n")

    if not flagged:
        print("  All interfaces are below the error threshold.")
        return 0

    col = "{:<28} {:<22} {:>11} {:>8} {:>11} {:>8} {:>7} {:>7}"
    header = col.format(
        "Interface", "Status", "Input Err", "CRC", "Out Drops", "Resets", "Runts", "Giants"
    )
    print(header)
    print("-" * len(header))

    for iface in sorted(flagged, key=worst_counter, reverse=True):
        print(
            col.format(
                iface["interface"],
                iface["status"],
                f"{iface['input_errors']:,}",
                f"{iface['crc_errors']:,}",
                f"{iface['output_drops']:,}",
                f"{iface['resets']:,}",
                f"{iface['runts']:,}",
                f"{iface['giants']:,}",
            )
        )

    return len(flagged)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Report interface error counters exceeding a threshold."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Flag interfaces with any counter at or above this value (default: 10)",
    )
    parser.add_argument("--output", metavar="FILE", help="Write full results to a JSON file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    client = ssh_connect(args.device, args.username, args.password, args.port)
    try:
        log.info("Running '%s'", COMMAND)
        raw = run_command(client, COMMAND)
    finally:
        client.close()

    interfaces = parse_interfaces(raw)
    if not interfaces:
        log.error("No interfaces parsed — verify device type and SSH output")
        sys.exit(1)

    log.info("Parsed %d interfaces", len(interfaces))
    flagged_count = print_report(interfaces, args.threshold, args.device)

    if args.output:
        payload = {
            "device": args.device,
            "threshold": args.threshold,
            "interfaces": interfaces,
        }
        with open(args.output, "w") as fh:
            json.dump(payload, fh, indent=2)
        log.info("Results written to %s", args.output)

    sys.exit(1 if flagged_count else 0)


if __name__ == "__main__":
    main()
```