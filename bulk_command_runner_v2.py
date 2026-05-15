```python
"""
ntp_checker.py — Network device NTP synchronization auditor

Purpose:
    Connects to multiple Cisco IOS/IOS-XE devices via SSH and audits NTP
    synchronization state. Reports sync status, stratum level, and reference
    clock for each device in a consolidated summary — useful for compliance
    checks and pre-change verification.

Usage:
    python ntp_checker.py --hosts 192.168.1.1 192.168.1.2 --username admin
    python ntp_checker.py --hosts-file devices.txt --username admin --key ~/.ssh/id_rsa
    python ntp_checker.py --hosts 10.0.0.1 --username admin --timeout 15

Prerequisites:
    pip install paramiko
    SSH must be enabled on target devices.
    Tested against Cisco IOS 15.x and IOS-XE 16.x.
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


@dataclass
class NTPResult:
    host: str
    reachable: bool = False
    synchronized: bool = False
    stratum: Optional[int] = None
    reference: Optional[str] = None
    error: Optional[str] = None


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 10) -> str:
    _, stdout, _ = client.exec_command(command, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


def parse_ntp_status(output: str) -> tuple:
    synchronized = bool(re.search(r"Clock is synchronized", output, re.IGNORECASE))
    stratum = None
    reference = None

    stratum_match = re.search(r"stratum\s+(\d+)", output, re.IGNORECASE)
    if stratum_match:
        stratum = int(stratum_match.group(1))

    ref_match = re.search(r"reference is\s+([\d.]+|[\w.-]+)", output, re.IGNORECASE)
    if ref_match:
        reference = ref_match.group(1)

    return synchronized, stratum, reference


def check_device(
    host: str,
    username: str,
    password: Optional[str],
    key_path: Optional[str],
    port: int,
    timeout: int,
) -> NTPResult:
    result = NTPResult(host=host)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if key_path:
            connect_kwargs["key_filename"] = key_path
        else:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        result.reachable = True

        output = run_command(client, "show ntp status", timeout=timeout)
        sync, stratum, reference = parse_ntp_status(output)
        result.synchronized = sync
        result.stratum = stratum
        result.reference = reference

    except paramiko.AuthenticationException:
        result.error = "authentication failed"
        log.warning("%s: authentication failed", host)
    except (paramiko.SSHException, OSError) as exc:
        result.error = str(exc)
        log.warning("%s: connection error: %s", host, exc)
    finally:
        client.close()

    return result


def print_report(results: list) -> None:
    synced = [r for r in results if r.synchronized]
    unsynced = [r for r in results if r.reachable and not r.synchronized]
    unreachable = [r for r in results if not r.reachable]

    col = max((len(r.host) for r in results), default=15)
    col = max(col, 4)

    print(f"\n{'HOST':<{col}}  {'STATUS':<14}  {'STRATUM':<9}  REFERENCE")
    print("-" * (col + 42))

    for r in results:
        if not r.reachable:
            err = f"  ({r.error})" if r.error else ""
            print(f"{r.host:<{col}}  {'UNREACHABLE':<14}{err}")
        elif r.synchronized:
            stratum = str(r.stratum) if r.stratum is not None else "?"
            ref = r.reference or "unknown"
            print(f"{r.host:<{col}}  {'SYNCED':<14}  {stratum:<9}  {ref}")
        else:
            print(f"{r.host:<{col}}  {'NOT SYNCED':<14}  {'N/A':<9}  N/A")

    print(
        f"\nSummary: {len(synced)} synced | "
        f"{len(unsynced)} not synced | "
        f"{len(unreachable)} unreachable"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit NTP synchronization status across Cisco network devices."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--hosts", nargs="+", metavar="HOST", help="Device IP(s) or hostnames"
    )
    group.add_argument(
        "--hosts-file", metavar="FILE", help="File with one host per line"
    )
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted and no key)")
    parser.add_argument("--key", metavar="PATH", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Connection timeout in seconds (default: 10)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if args.hosts_file:
        try:
            with open(args.hosts_file) as fh:
                hosts = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except OSError as exc:
            log.error("Cannot read hosts file: %s", exc)
            return 1
    else:
        hosts = args.hosts

    password = args.password
    if not args.key and not password:
        password = getpass.getpass(f"Password for {args.username}: ")

    results = []
    for host in hosts:
        log.info("Checking %s", host)
        result = check_device(
            host=host,
            username=args.username,
            password=password,
            key_path=args.key,
            port=args.port,
            timeout=args.timeout,
        )
        results.append(result)

    print_report(results)

    unsynced_count = sum(1 for r in results if r.reachable and not r.synchronized)
    return 1 if unsynced_count else 0


if __name__ == "__main__":
    sys.exit(main())
```