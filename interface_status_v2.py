Interface Error Counter Monitor

Connects to a Cisco IOS device via SSH and collects per-interface error
statistics (input errors, CRC, output errors, drops, collisions), reporting
interfaces that exceed a configurable total-error threshold.

Usage:
    python interface_errors.py -H 192.168.1.1 -u admin -p secret
    python interface_errors.py -H 192.168.1.1 -u admin -p secret --threshold 100
    python interface_errors.py -H 192.168.1.1 -u admin -p secret --interface Gi0/1 --format json

Prerequisites:
    pip install paramiko
    Device must support: show interfaces
"""

import argparse
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

_SHOW_CMD = "show interfaces"
_CONNECT_TIMEOUT = 30

_RE_IFACE = re.compile(r"^(\S+)\s+is\s+(up|down|administratively down)", re.MULTILINE)
_RE_INPUT_ERR = re.compile(r"(\d+) input errors")
_RE_CRC = re.compile(r"(\d+) CRC")
_RE_OUTPUT_ERR = re.compile(r"(\d+) output errors")
_RE_OUTPUT_DROP = re.compile(r"(\d+) output drops")
_RE_COLLISION = re.compile(r"(\d+) collision")


def _connect(host, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=_CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as exc:
        log.error("SSH connection to %s failed: %s", host, exc)
        raise
    return client


def _run(client, command):
    chan = client.get_transport().open_session()
    chan.settimeout(_CONNECT_TIMEOUT)
    chan.exec_command(command)
    buf = b""
    while True:
        chunk = chan.recv(4096)
        if not chunk:
            break
        buf += chunk
    chan.close()
    return buf.decode("utf-8", errors="replace")


def _extract(pattern, text, default=0):
    m = pattern.search(text)
    return int(m.group(1)) if m else default


def parse_error_counters(raw, iface_filter=None):
    """Return list of dicts with error counters per interface."""
    blocks = re.split(r"\n(?=\S)", raw)
    results = []
    for block in blocks:
        m = _RE_IFACE.match(block)
        if not m:
            continue
        name, state = m.group(1), m.group(2)
        if iface_filter and iface_filter.lower() not in name.lower():
            continue
        input_err = _extract(_RE_INPUT_ERR, block)
        crc = _extract(_RE_CRC, block)
        output_err = _extract(_RE_OUTPUT_ERR, block)
        output_drop = _extract(_RE_OUTPUT_DROP, block)
        collisions = _extract(_RE_COLLISION, block)
        results.append({
            "interface": name,
            "state": state,
            "input_errors": input_err,
            "crc_errors": crc,
            "output_errors": output_err,
            "output_drops": output_drop,
            "collisions": collisions,
            "total_errors": input_err + crc + output_err + output_drop + collisions,
        })
    return results


def _print_table(records):
    if not records:
        print("No interfaces matched the criteria.")
        return
    hdr = f"{'Interface':<32} {'State':<22} {'InErr':>7} {'CRC':>7} {'OutErr':>7} {'Drops':>7} {'Coll':>7} {'Total':>8}"
    print(hdr)
    print("-" * len(hdr))
    for r in records:
        print(
            f"{r['interface']:<32} {r['state']:<22} "
            f"{r['input_errors']:>7} {r['crc_errors']:>7} "
            f"{r['output_errors']:>7} {r['output_drops']:>7} "
            f"{r['collisions']:>7} {r['total_errors']:>8}"
        )


def _parse_args():
    p = argparse.ArgumentParser(
        description="Report per-interface error counters from a Cisco IOS device."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--threshold",
        type=int,
        default=0,
        help="Only show interfaces with total errors above this value (default: 0 = show all)",
    )
    p.add_argument(
        "--interface",
        metavar="NAME",
        default=None,
        help="Filter output to interfaces whose name contains NAME (case-insensitive)",
    )
    p.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = _connect(args.host, args.port, args.username, args.password)
    except Exception:
        sys.exit(1)

    try:
        log.debug("Executing: %s", _SHOW_CMD)
        raw = _run(client, _SHOW_CMD)
    finally:
        client.close()

    records = parse_error_counters(raw, iface_filter=args.interface)

    if not records:
        log.error("No interface data parsed — verify the device supports '%s'", _SHOW_CMD)
        sys.exit(1)

    if args.threshold > 0:
        records = [r for r in records if r["total_errors"] > args.threshold]

    log.info(
        "Reporting %d interface(s) (threshold=%d)", len(records), args.threshold
    )

    if args.format == "json":
        print(json.dumps(records, indent=2))
    else:
        _print_table(records)