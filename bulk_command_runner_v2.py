```python
"""
ntp_compliance.py — NTP server compliance auditor for network devices.

Connects to a Cisco IOS/NX-OS device via SSH and verifies that the configured
NTP servers match an expected reference list. Exits with code 2 on non-compliance
so it integrates cleanly into monitoring pipelines or CI checks.

Usage:
    python ntp_compliance.py -H 192.168.1.1 -u admin -p secret \
        --expected 10.0.0.1,10.0.0.2

    python ntp_compliance.py -H 192.168.1.1 -u admin -k ~/.ssh/id_rsa \
        --expected 10.0.0.1 --strict --timeout 30

Prerequisites:
    pip install paramiko
"""

import argparse
import logging
import re
import sys
import time
from typing import Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def connect(
    host: str,
    username: str,
    password: Optional[str],
    key_file: Optional[str],
    port: int,
    timeout: int,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client: paramiko.SSHClient, command: str, wait: float = 1.5) -> str:
    channel = client.invoke_shell()
    channel.settimeout(15)
    time.sleep(wait)
    channel.recv(8192)  # drain banner/prompt
    channel.send(command + "\n")
    time.sleep(wait)
    output = b""
    while channel.recv_ready():
        output += channel.recv(8192)
    channel.close()
    return output.decode("utf-8", errors="replace")


def parse_ntp_associations(output: str) -> set:
    """Extract peer IPs from 'show ntp associations' output."""
    servers = set()
    # Matches IOS association lines: *~10.0.0.1  127.127.1.1  ...
    # Leading status chars: * + - x space, optionally followed by ~
    ip_re = re.compile(
        r"^[* +\-x~\s]{0,3}([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s",
        re.MULTILINE,
    )
    for m in ip_re.finditer(output):
        addr = m.group(1)
        if not addr.startswith(("0.", "127.")):
            servers.add(addr)
    return servers


def audit_ntp(client: paramiko.SSHClient, expected: set) -> dict:
    log.info("Fetching NTP associations")
    assoc_out = run_command(client, "show ntp associations")

    log.info("Fetching NTP status")
    status_out = run_command(client, "show ntp status")

    configured = parse_ntp_associations(assoc_out)
    synchronized = "synchronized" in status_out.lower()

    ref_match = re.search(r"reference\s+is\s+([0-9.]+)", status_out, re.IGNORECASE)
    ref_server = ref_match.group(1) if ref_match else "unknown"

    stratum_match = re.search(r"stratum\s+(\d+)", status_out, re.IGNORECASE)
    stratum = int(stratum_match.group(1)) if stratum_match else None

    missing = expected - configured
    unexpected = configured - expected

    return {
        "configured": sorted(configured),
        "expected": sorted(expected),
        "missing": sorted(missing),
        "unexpected": sorted(unexpected),
        "synchronized": synchronized,
        "reference": ref_server,
        "stratum": stratum,
        "compliant": not missing and synchronized,
    }


def print_report(host: str, result: dict, strict: bool) -> None:
    compliant = result["compliant"] and (not strict or not result["unexpected"])
    status = "PASS" if compliant else "FAIL"
    stratum = str(result["stratum"]) if result["stratum"] is not None else "unknown"

    print(f"\n{'='*50}")
    print(f"  NTP Compliance Report — {host}")
    print(f"{'='*50}")
    print(f"  Result       : {status}")
    print(f"  Synchronized : {'Yes' if result['synchronized'] else 'No'}")
    print(f"  Reference    : {result['reference']}")
    print(f"  Stratum      : {stratum}")
    print(f"  Configured   : {', '.join(result['configured']) or 'none detected'}")
    print(f"  Expected     : {', '.join(result['expected'])}")
    if result["missing"]:
        print(f"  [!] Missing  : {', '.join(result['missing'])}")
    if result["unexpected"]:
        flag = "[!]" if strict else "[ ]"
        print(f"  {flag} Extra    : {', '.join(result['unexpected'])}")
    print(f"{'='*50}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit NTP server compliance on a Cisco network device."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("-k", "--key-file", default=None, help="SSH private key path")
    parser.add_argument(
        "--expected",
        required=True,
        help="Comma-separated expected NTP server IPs (e.g. 10.0.0.1,10.0.0.2)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout (s)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also fail if unexpected NTP servers are present",
    )
    parser.add_argument(
        "--max-stratum",
        type=int,
        default=None,
        help="Fail if device stratum exceeds this value",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.password and not args.key_file:
        log.error("Provide --password or --key-file")
        return 1

    expected = {s.strip() for s in args.expected.split(",") if s.strip()}
    if not expected:
        log.error("--expected must contain at least one IP address")
        return 1

    try:
        log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
        client = connect(
            args.host, args.username, args.password,
            args.key_file, args.port, args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("SSH connection failed: %s", exc)
        return 1

    try:
        result = audit_ntp(client, expected)
    except Exception as exc:
        log.error("Audit error: %s", exc)
        return 1
    finally:
        client.close()

    print_report(args.host, result, args.strict)

    if args.max_stratum and result["stratum"] and result["stratum"] > args.max_stratum:
        log.warning(
            "Stratum %d exceeds maximum allowed %d",
            result["stratum"],
            args.max_stratum,
        )
        return 2

    compliant = result["compliant"] and (not args.strict or not result["unexpected"])
    return 0 if compliant else 2


if __name__ == "__main__":
    sys.exit(main())
```