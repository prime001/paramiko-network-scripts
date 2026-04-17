```python
"""
interface_errors.py - Interface Error Counter Monitor

Purpose:
    Connects to a Cisco IOS/IOS-XE device via SSH and retrieves per-interface
    error counters (CRC, input errors, output drops, resets, etc.).  Reports
    any interface whose error rate exceeds a configurable threshold, making it
    useful for proactive fault detection and capacity planning.

Usage:
    python interface_errors.py -d 192.168.1.1 -u admin -p secret
    python interface_errors.py -d 10.0.0.1 -u admin --threshold 100 --csv out.csv
    python interface_errors.py -d 10.0.0.1 -u admin -f GigabitEthernet

Prerequisites:
    pip install paramiko
    Target device must have SSH enabled and the user must have priv 1+.
"""

import argparse
import csv
import logging
import re
import sys
from getpass import getpass

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

RECV_TIMEOUT = 15
RECV_BYTES = 65535


def ssh_exec(client: paramiko.SSHClient, command: str) -> str:
    """Execute a command and return the full output string."""
    chan = client.get_transport().open_session()
    chan.settimeout(RECV_TIMEOUT)
    chan.exec_command(command)
    output = b""
    while True:
        chunk = chan.recv(RECV_BYTES)
        if not chunk:
            break
        output += chunk
    chan.close()
    return output.decode("utf-8", errors="replace")


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info("Connecting to %s:%s", host, port)
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
    )
    return client


def parse_interface_errors(raw: str) -> list[dict]:
    """
    Parse 'show interfaces' output into a list of per-interface counter dicts.
    Handles multi-line blocks separated by blank lines or new interface headers.
    """
    results = []
    blocks = re.split(r"\n(?=\S)", raw)

    iface_re = re.compile(r"^(\S+)\s+is\s+(up|down|administratively down)", re.I)
    counter_patterns = {
        "input_errors":   re.compile(r"(\d+)\s+input errors"),
        "crc":            re.compile(r"(\d+)\s+CRC"),
        "output_drops":   re.compile(r"(\d+)\s+output drops"),
        "input_drops":    re.compile(r"(\d+)\s+input drops"),
        "resets":         re.compile(r"(\d+)\s+interface resets"),
        "giants":         re.compile(r"(\d+)\s+giants"),
        "runts":          re.compile(r"(\d+)\s+runts"),
        "output_errors":  re.compile(r"(\d+)\s+output errors"),
    }

    for block in blocks:
        m = iface_re.match(block)
        if not m:
            continue
        record = {
            "interface": m.group(1),
            "status": m.group(2).lower(),
        }
        for key, pattern in counter_patterns.items():
            cm = pattern.search(block)
            record[key] = int(cm.group(1)) if cm else 0
        record["total_errors"] = (
            record["input_errors"] + record["output_errors"] + record["output_drops"]
        )
        results.append(record)

    return results


def filter_interfaces(
    records: list[dict], name_filter: str | None, threshold: int
) -> list[dict]:
    filtered = records
    if name_filter:
        filtered = [r for r in filtered if name_filter.lower() in r["interface"].lower()]
    return [r for r in filtered if r["total_errors"] >= threshold]


def print_table(records: list[dict]) -> None:
    if not records:
        print("No interfaces exceeded the error threshold.")
        return
    hdr = f"{'Interface':<30} {'Status':<8} {'InErr':>7} {'CRC':>7} {'OutDrop':>8} {'Resets':>7} {'Total':>7}"
    print(hdr)
    print("-" * len(hdr))
    for r in records:
        print(
            f"{r['interface']:<30} {r['status']:<8} "
            f"{r['input_errors']:>7} {r['crc']:>7} "
            f"{r['output_drops']:>8} {r['resets']:>7} "
            f"{r['total_errors']:>7}"
        )


def write_csv(records: list[dict], path: str) -> None:
    if not records:
        log.info("No data to write.")
        return
    fields = list(records[0].keys())
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    log.info("Results written to %s", path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Report interface error counters from a Cisco device via SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--threshold",
        type=int,
        default=0,
        help="Only show interfaces with total errors >= this value (default: 0)",
    )
    parser.add_argument(
        "-f", "--filter",
        dest="name_filter",
        default=None,
        help="Filter interfaces by name substring (e.g. GigabitEthernet)",
    )
    parser.add_argument("--csv", dest="csv_path", default=None, help="Write results to CSV file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = connect(args.device, args.port, args.username, password)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        log.info("Retrieving interface counters...")
        raw = ssh_exec(client, "show interfaces")
    except Exception as exc:
        log.error("Failed to retrieve data: %s", exc)
        client.close()
        sys.exit(1)
    finally:
        client.close()

    records = parse_interface_errors(raw)
    if not records:
        log.error("Could not parse any interface data. Check device output format.")
        sys.exit(1)

    log.info("Parsed %d interfaces", len(records))
    visible = filter_interfaces(records, args.name_filter, args.threshold)
    print_table(visible)

    if args.csv_path:
        write_csv(visible, args.csv_path)


if __name__ == "__main__":
    main()
```