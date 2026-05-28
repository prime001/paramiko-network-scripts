NTP Synchronization Status Checker for network devices.

Connects via SSH (paramiko) to one or more Cisco IOS/IOS-XE devices and
reports NTP synchronization state, stratum, reference clock, and offset.
Useful for verifying time consistency across a fleet before/after maintenance,
auditing NTP compliance, or troubleshooting clock-sensitive protocols (OSPF,
BGP, certificates, logging correlation).

Usage:
    python ntp_sync_check.py -H 192.168.1.1 -u admin -p secret
    python ntp_sync_check.py -H 192.168.1.1 192.168.1.2 -u admin --key ~/.ssh/id_rsa
    python ntp_sync_check.py --hosts-file hosts.txt -u admin -p secret --timeout 15

Prerequisites:
    pip install paramiko

Exit codes:
    0  All devices synchronized
    1  One or more devices not synchronized or unreachable
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class NTPStatus:
    host: str
    synced: bool
    stratum: Optional[int]
    reference: Optional[str]
    offset_ms: Optional[float]
    error: Optional[str] = None


def _run_command(client: paramiko.SSHClient, command: str, timeout: int) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    if err.strip():
        logger.debug("stderr: %s", err.strip())
    return out


def _parse_ntp_status(output: str) -> dict:
    result = {"synced": False, "stratum": None, "reference": None, "offset_ms": None}

    if re.search(r"Clock is synchronized", output, re.IGNORECASE):
        result["synced"] = True

    m = re.search(r"stratum\s+(\d+)", output, re.IGNORECASE)
    if m:
        result["stratum"] = int(m.group(1))

    m = re.search(r"reference is\s+(\S+)", output, re.IGNORECASE)
    if m:
        result["reference"] = m.group(1)

    # IOS reports offset in msec; IOS-XE may report in usec — normalize to ms
    m = re.search(r"offset\s+is\s+([\-\d.]+)\s+(msec|usec)", output, re.IGNORECASE)
    if m:
        val = float(m.group(1))
        result["offset_ms"] = val / 1000.0 if m.group(2).lower() == "usec" else val

    return result


def check_ntp(
    host: str,
    username: str,
    password: Optional[str],
    key_filename: Optional[str],
    port: int,
    timeout: int,
) -> NTPStatus:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs: dict = dict(
            hostname=host,
            port=port,
            username=username,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        if key_filename:
            connect_kwargs["key_filename"] = key_filename
            connect_kwargs["look_for_keys"] = True
        else:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        logger.debug("Connected to %s", host)

        output = _run_command(client, "show ntp status", timeout)
        parsed = _parse_ntp_status(output)

        return NTPStatus(
            host=host,
            synced=parsed["synced"],
            stratum=parsed["stratum"],
            reference=parsed["reference"],
            offset_ms=parsed["offset_ms"],
        )
    except paramiko.AuthenticationException:
        return NTPStatus(host=host, synced=False, stratum=None, reference=None,
                         offset_ms=None, error="Authentication failed")
    except (paramiko.SSHException, OSError) as exc:
        return NTPStatus(host=host, synced=False, stratum=None, reference=None,
                         offset_ms=None, error=str(exc))
    finally:
        client.close()


def _load_hosts_file(path: str) -> list:
    hosts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def _print_results(results: list, verbose: bool) -> int:
    width = max(len(r.host) for r in results)
    failures = 0

    for r in results:
        if r.error:
            status = f"ERROR     {r.error}"
            failures += 1
        elif r.synced:
            parts = ["SYNCED"]
            if r.stratum is not None:
                parts.append(f"stratum={r.stratum}")
            if r.reference:
                parts.append(f"ref={r.reference}")
            if r.offset_ms is not None:
                parts.append(f"offset={r.offset_ms:+.2f}ms")
            status = "  ".join(parts)
        else:
            status = "NOT SYNCED"
            failures += 1

        print(f"{r.host:<{width}}  {status}")

    if verbose:
        synced = len(results) - failures
        print(f"\n{synced}/{len(results)} device(s) synchronized")

    return failures


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check NTP synchronization status on network devices via SSH.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    host_group = p.add_mutually_exclusive_group(required=True)
    host_group.add_argument("-H", "--hosts", nargs="+", metavar="HOST",
                            help="One or more device IPs or hostnames")
    host_group.add_argument("--hosts-file", metavar="FILE",
                            help="File listing one host per line (# lines skipped)")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    cred = p.add_mutually_exclusive_group(required=True)
    cred.add_argument("-p", "--password", help="SSH password")
    cred.add_argument("--key", metavar="FILE", dest="key_filename",
                      help="Path to SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=20,
                   help="Connect/command timeout in seconds (default: 20)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show summary line and extra info")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    logging.getLogger().setLevel(log_level)

    hosts = args.hosts if args.hosts else _load_hosts_file(args.hosts_file)
    if not hosts:
        parser.error("No hosts specified")

    results = []
    for host in hosts:
        logger.info("Checking %s", host)
        results.append(check_ntp(
            host=host,
            username=args.username,
            password=args.password,
            key_filename=args.key_filename,
            port=args.port,
            timeout=args.timeout,
        ))

    failures = _print_results(results, args.verbose)
    sys.exit(1 if failures else 0)