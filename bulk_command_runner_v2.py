```python
"""
NTP Synchronization Status Checker

Connects to Cisco IOS/IOS-XE network devices via SSH and reports NTP
synchronization state, stratum level, reference clock, and clock offset.
Useful for verifying NTP health across a fleet before change windows or
after network modifications that could disrupt time synchronization.

Usage:
    Single device:
        python ntp_status.py -H 192.168.1.1 -u admin -p secret

    Multiple devices (comma-separated):
        python ntp_status.py -H 192.168.1.1,192.168.1.2 -u admin -p secret

    From hosts file (one host per line, # for comments):
        python ntp_status.py --hosts-file devices.txt -u admin --ask-pass

    CSV output:
        python ntp_status.py --hosts-file devices.txt -u admin -p secret --csv

Prerequisites:
    pip install paramiko
    Devices must allow SSH; user account needs read access to NTP commands.
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import csv
import getpass
import logging
import re
import sys
from typing import Dict, List, Optional

import paramiko

logging.basicConfig(
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.WARNING,
)
logger = logging.getLogger(__name__)


def _ssh_connect(
    host: str, username: str, password: str, port: int, timeout: int
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run_command(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        logger.debug("stderr for '%s': %s", command, err)
    return output


def parse_ntp_status(output: str) -> Dict[str, Optional[str]]:
    """Extract key fields from 'show ntp status' output."""
    result: Dict[str, Optional[str]] = {
        "synchronized": "unknown",
        "stratum": None,
        "reference": None,
        "offset_ms": None,
    }

    sync_match = re.search(r"Clock is (synchronized|unsynchronized)", output, re.IGNORECASE)
    if sync_match:
        result["synchronized"] = sync_match.group(1).lower()

    stratum_match = re.search(r"stratum\s+(\d+)", output, re.IGNORECASE)
    if stratum_match:
        result["stratum"] = stratum_match.group(1)

    ref_match = re.search(r"reference is\s+(\S+)", output, re.IGNORECASE)
    if ref_match:
        result["reference"] = ref_match.group(1)

    offset_match = re.search(r"offset\s+([+-]?[\d.]+)\s+msec", output, re.IGNORECASE)
    if offset_match:
        result["offset_ms"] = offset_match.group(1)

    return result


def check_device(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 15,
) -> Dict:
    result: Dict = {"host": host, "status": "error", "error": None}
    client = None
    try:
        client = _ssh_connect(host, username, password, port, timeout)
        raw = _run_command(client, "show ntp status", timeout=timeout)
        result.update(parse_ntp_status(raw))
        result["status"] = "ok"
    except paramiko.AuthenticationException:
        result["error"] = "authentication failed"
        logger.error("%s: authentication failed", host)
    except paramiko.SSHException as exc:
        result["error"] = f"SSH error: {exc}"
        logger.error("%s: SSH error: %s", host, exc)
    except OSError as exc:
        result["error"] = f"connection failed: {exc}"
        logger.error("%s: %s", host, exc)
    finally:
        if client:
            client.close()
    return result


def print_table(results: List[Dict]) -> None:
    header = (
        f"{'HOST':<20} {'SYNC':<15} {'STRATUM':<9} {'REFERENCE':<18} {'OFFSET (ms)':<13} ERROR"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        sync = r.get("synchronized") or "-"
        stratum = r.get("stratum") or "-"
        ref = r.get("reference") or "-"
        offset = r.get("offset_ms") or "-"
        error = r.get("error") or ""
        print(f"{r['host']:<20} {sync:<15} {stratum:<9} {ref:<18} {offset:<13} {error}")


def print_csv(results: List[Dict]) -> None:
    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=["host", "status", "synchronized", "stratum", "reference", "offset_ms", "error"],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(results)


def load_hosts(path: str) -> List[str]:
    with open(path) as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check NTP synchronization status on network devices via SSH.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--hosts", help="Comma-separated device IPs/hostnames")
    group.add_argument("--hosts-file", metavar="FILE", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (omit to prompt)")
    parser.add_argument(
        "--ask-pass", action="store_true", help="Always prompt for password"
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=15, help="Connection timeout in seconds (default: 15)"
    )
    parser.add_argument("--csv", action="store_true", help="Write results as CSV to stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or not password:
        password = getpass.getpass(f"SSH password for {args.username}: ")

    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    else:
        try:
            hosts = load_hosts(args.hosts_file)
        except OSError as exc:
            print(f"Error reading hosts file: {exc}", file=sys.stderr)
            return 1

    if not hosts:
        print("No hosts to check.", file=sys.stderr)
        return 1

    results = []
    for host in hosts:
        logger.info("Checking %s", host)
        results.append(check_device(host, args.username, password, args.port, args.timeout))

    if args.csv:
        print_csv(results)
    else:
        print_table(results)
        failed = sum(1 for r in results if r["status"] == "error")
        unsynced = sum(1 for r in results if r.get("synchronized") == "unsynchronized")
        print(
            f"\n{len(results)} device(s) | {failed} unreachable | {unsynced} unsynchronized"
        )

    any_issue = any(
        r["status"] == "error" or r.get("synchronized") == "unsynchronized"
        for r in results
    )
    return 1 if any_issue else 0


if __name__ == "__main__":
    sys.exit(main())
```