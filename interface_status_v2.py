Since file write needs approval, here is the complete script content:

```
"""
Interface Error Counter Monitor
================================
Polls Cisco IOS/IOS-XE interface error counters and flags interfaces that
exceed configurable thresholds for CRC errors, input drops, output drops,
input errors, or output errors.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \
        --crc-threshold 10 --drop-threshold 100 --json
    python interface_error_monitor.py -d 192.168.1.1 -u admin \
        --key ~/.ssh/id_rsa --interface GigabitEthernet0/1

Prerequisites:
    pip install paramiko
    Device must have SSH enabled and the account needs privilege 1+.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.WARNING,
)
log = logging.getLogger(__name__)

_RE_IFACE = re.compile(r"^(\S+)\s+is\s+(up|down|administratively down)", re.M)
_RE_INPUT_ERRORS = re.compile(r"(\d+)\s+input errors")
_RE_CRC = re.compile(r"(\d+)\s+CRC")
_RE_OUTPUT_ERRORS = re.compile(r"(\d+)\s+output errors")
_RE_INPUT_DROPS = re.compile(r"(\d+)\s+no buffer|(\d+)\s+input drops", re.I)
_RE_OUTPUT_DROPS = re.compile(r"(\d+)\s+output drops")


def _ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr from device: %s", err)
    return out


def connect(host: str, port: int, username: str, password: str | None,
            key_path: str | None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(hostname=host, port=port, username=username, timeout=15)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def fetch_interface_output(client: paramiko.SSHClient,
                           interface: str | None) -> str:
    if interface:
        return _ssh_exec(client, f"show interfaces {interface}")
    return _ssh_exec(client, "show interfaces")


def _first_int(pattern: re.Pattern, text: str) -> int:
    m = pattern.search(text)
    if not m:
        return 0
    for g in m.groups():
        if g is not None:
            return int(g)
    return 0


def parse_counters(raw: str) -> list[dict]:
    records: list[dict] = []
    blocks = re.split(r"(?=^\S)", raw, flags=re.M)
    for block in blocks:
        m = _RE_IFACE.match(block)
        if not m:
            continue
        records.append({
            "interface": m.group(1),
            "status": m.group(2),
            "input_errors": _first_int(_RE_INPUT_ERRORS, block),
            "crc_errors": _first_int(_RE_CRC, block),
            "output_errors": _first_int(_RE_OUTPUT_ERRORS, block),
            "input_drops": _first_int(_RE_INPUT_DROPS, block),
            "output_drops": _first_int(_RE_OUTPUT_DROPS, block),
        })
    return records


def apply_thresholds(records: list[dict], crc_thresh: int, drop_thresh: int,
                     error_thresh: int) -> list[dict]:
    flagged = []
    for r in records:
        violations = []
        if r["crc_errors"] >= crc_thresh:
            violations.append(f"CRC={r['crc_errors']}")
        if r["input_drops"] + r["output_drops"] >= drop_thresh:
            violations.append(
                f"drops={r['input_drops'] + r['output_drops']}"
            )
        if r["input_errors"] + r["output_errors"] >= error_thresh:
            violations.append(
                f"errors={r['input_errors'] + r['output_errors']}"
            )
        if violations:
            r["violations"] = violations
            flagged.append(r)
    return flagged


def print_report(device: str, all_records: list[dict],
                 flagged: list[dict]) -> None:
    print(f"\nDevice: {device}  |  Interfaces polled: {len(all_records)}"
          f"  |  Flagged: {len(flagged)}")
    print("-" * 72)
    if not flagged:
        print("No interfaces exceeded thresholds.")
        return
    fmt = "  {:<36} {:<8} {}"
    print(fmt.format("Interface", "Status", "Violations"))
    print(fmt.format("-" * 36, "-" * 6, "-" * 26))
    for r in flagged:
        print(fmt.format(r["interface"], r["status"],
                         ", ".join(r["violations"])))


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Report Cisco IOS interfaces with elevated error counters."
    )
    ap.add_argument("-d", "--device", required=True, help="Device hostname/IP")
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password", default=None,
                    help="Omit to be prompted securely")
    ap.add_argument("--key", dest="key_path", default=None,
                    help="Path to SSH private key (alternative to password)")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--interface", default=None,
                    help="Limit to a single interface (default: all)")
    ap.add_argument("--crc-threshold", type=int, default=1,
                    help="Flag interface when CRC errors >= N (default: 1)")
    ap.add_argument("--drop-threshold", type=int, default=50,
                    help="Flag when total drops >= N (default: 50)")
    ap.add_argument("--error-threshold", type=int, default=50,
                    help="Flag when total input+output errors >= N (default: 50)")
    ap.add_argument("--all", dest="show_all", action="store_true",
                    help="Print all interfaces, not just flagged ones")
    ap.add_argument("--json", dest="json_out", action="store_true",
                    help="Emit JSON instead of formatted table")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_path:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        log.debug("Connecting to %s:%d", args.device, args.port)
        client = connect(args.device, args.port, args.username,
                         password, args.key_path)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        raw = fetch_interface_output(client, args.interface)
    finally:
        client.close()

    records = parse_counters(raw)
    if not records:
        log.error("No interface data parsed — verify device type and credentials")
        sys.exit(1)

    flagged = apply_thresholds(
        records, args.crc_threshold, args.drop_threshold, args.error_threshold
    )

    if args.json_out:
        output = {
            "device": args.device,
            "total_interfaces": len(records),
            "flagged": flagged if not args.show_all else records,
        }
        print(json.dumps(output, indent=2))
    else:
        display = records if args.show_all else flagged
        print_report(args.device, records, display)

    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
```