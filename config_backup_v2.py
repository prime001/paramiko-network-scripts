Interface Error Rate Monitor

Connects to a Cisco IOS device via SSH and audits all interfaces for elevated
error counters: CRC errors, input errors, output drops, giants, runts, and
interface resets. Reports interfaces exceeding configurable thresholds.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin --password secret
    python interface_error_monitor.py -H 192.168.1.1 -u admin -k ~/.ssh/id_rsa \\
        --crc-threshold 5 --drop-threshold 50 --output json
    python interface_error_monitor.py -H 192.168.1.1 -u admin --password s3cr3t \\
        --all --output csv > errors.csv

Prerequisites:
    pip install paramiko
    Device must have SSH enabled with the user at privilege level 1 or higher.
    IOS terminal paging is disabled automatically via 'terminal length 0'.
"""

import argparse
import csv
import json
import logging
import re
import sys
import time

import paramiko

LOG = logging.getLogger(__name__)


def build_client(host, port, username, password=None, key_file=None, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host, port=port, username=username,
        timeout=timeout, look_for_keys=False, allow_agent=False,
    )
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def send(shell, command, delay=1.5):
    shell.send(command + "\n")
    time.sleep(delay)
    buf = b""
    while shell.recv_ready():
        buf += shell.recv(65535)
    return buf.decode("utf-8", errors="replace")


def collect_raw(shell):
    send(shell, "terminal length 0", delay=0.5)
    raw = send(shell, "show interfaces", delay=2.5)
    while shell.recv_ready():
        raw += shell.recv(65535).decode("utf-8", errors="replace")
    return raw


def parse_interfaces(raw):
    results = []
    blocks = re.split(
        r"(?=^\S[\w/.:-]+\s+is\s+(?:up|down|administratively\s+down))",
        raw,
        flags=re.MULTILINE,
    )
    for block in blocks:
        name_m = re.match(r"^(\S[\w/.:-]+)\s+is\s+", block)
        if not name_m:
            continue

        def pull(pattern, default=0):
            m = re.search(pattern, block)
            return int(m.group(1)) if m else default

        results.append({
            "interface":     name_m.group(1),
            "input_errors":  pull(r"(\d+) input errors"),
            "crc":           pull(r"(\d+) CRC"),
            "giants":        pull(r"(\d+) giants"),
            "runts":         pull(r"(\d+) runts"),
            "output_drops":  pull(r"(\d+) output drops"),
            "resets":        pull(r"(\d+) interface resets"),
        })
    return results


def apply_thresholds(interfaces, crc_min, input_min, drop_min):
    return [
        i for i in interfaces
        if i["crc"] >= crc_min
        or i["input_errors"] >= input_min
        or i["output_drops"] >= drop_min
    ]


def render_table(rows):
    if not rows:
        print("No interfaces exceed the configured thresholds.")
        return
    hdr = f"{'Interface':<26}{'CRC':>8}{'InputErr':>10}{'Drops':>8}{'Giants':>8}{'Runts':>7}{'Resets':>8}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(
            f"{r['interface']:<26}{r['crc']:>8}{r['input_errors']:>10}"
            f"{r['output_drops']:>8}{r['giants']:>8}{r['runts']:>7}{r['resets']:>8}"
        )


def render_json(rows):
    print(json.dumps(rows, indent=2))


def render_csv(rows):
    if not rows:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Audit interface error counters on a Cisco IOS device."
    )
    parser.add_argument("-H", "--host", required=True)
    parser.add_argument("-P", "--port", type=int, default=22)
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("-k", "--key-file")
    parser.add_argument(
        "--crc-threshold", type=int, default=1,
        help="Flag interfaces with CRC >= N (default: 1)",
    )
    parser.add_argument(
        "--input-threshold", type=int, default=10,
        help="Flag interfaces with input errors >= N (default: 10)",
    )
    parser.add_argument(
        "--drop-threshold", type=int, default=10,
        help="Flag interfaces with output drops >= N (default: 10)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Report all interfaces regardless of thresholds",
    )
    parser.add_argument(
        "--output", choices=["table", "json", "csv"], default="table",
    )
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.password and not args.key_file:
        parser.error("Provide --password or --key-file")

    LOG.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        client = build_client(
            args.host, args.port, args.username,
            password=args.password, key_file=args.key_file,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        LOG.error("Authentication failed")
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        LOG.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell(width=220, height=50)
        time.sleep(0.8)
        if shell.recv_ready():
            shell.recv(65535)
        LOG.info("Collecting interface counters...")
        raw = collect_raw(shell)
    finally:
        client.close()

    interfaces = parse_interfaces(raw)
    LOG.info("Parsed %d interfaces", len(interfaces))

    if args.all:
        rows = interfaces
    else:
        rows = apply_thresholds(
            interfaces, args.crc_threshold, args.input_threshold, args.drop_threshold,
        )
        LOG.info("%d interface(s) flagged", len(rows))

    {"table": render_table, "json": render_json, "csv": render_csv}[args.output](rows)

    sys.exit(1 if rows and not args.all else 0)


if __name__ == "__main__":
    main()