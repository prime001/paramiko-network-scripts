ntp_status.py — NTP Synchronization Status Checker

Connects to Cisco IOS/IOS-XE devices via SSH and reports NTP synchronization
state, stratum, and reference clock. Optionally verifies that a required set
of NTP servers is configured and that each device is actively synchronized.

Usage:
    python ntp_status.py -d 192.168.1.1 -u admin -p secret
    python ntp_status.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python ntp_status.py --host-file devices.txt -u admin --expected 10.0.0.1 10.0.0.2

Prerequisites:
    pip install paramiko

Exit code is 0 only when every device is reachable, synchronized, and
(if --expected is given) has all required NTP servers configured.
"""

import argparse
import getpass
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=10):
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
        kwargs["look_for_keys"] = True
    elif password:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=15):
    _, stdout, _ = client.exec_command(command, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


def parse_ntp_status(output):
    """Return sync state, stratum, and reference from 'show ntp status'."""
    result = {
        "synchronized": False,
        "clock_state": "unknown",
        "stratum": None,
        "reference": None,
    }
    m = re.search(r"Clock is (\w+)", output)
    if m:
        result["clock_state"] = m.group(1).lower()
        result["synchronized"] = result["clock_state"] == "synchronized"

    m = re.search(r"stratum\s+(\d+)", output, re.IGNORECASE)
    if m:
        result["stratum"] = int(m.group(1))

    m = re.search(r"reference is\s+(\S+)", output, re.IGNORECASE)
    if m:
        result["reference"] = m.group(1)

    return result


def parse_ntp_associations(output):
    """Return set of peer IPs from 'show ntp associations'."""
    servers = set()
    for line in output.splitlines():
        if not line.strip() or "address" in line.lower() or "===" in line:
            continue
        stripped = re.sub(r"^[~*+\-x#\s]+", "", line)
        m = re.match(r"(\d{1,3}(?:\.\d{1,3}){3})", stripped)
        if m:
            servers.add(m.group(1))
    return servers


def check_device(host, username, password, key_file, port, expected_servers, timeout):
    result = {
        "host": host,
        "reachable": False,
        "synchronized": False,
        "clock_state": "unknown",
        "stratum": None,
        "reference": None,
        "configured_servers": set(),
        "missing_servers": set(),
        "error": None,
    }
    try:
        client = ssh_connect(host, username, password, key_file, port, timeout)
        status_out = run_command(client, "show ntp status")
        assoc_out = run_command(client, "show ntp associations")
        client.close()

        result["reachable"] = True
        result.update(parse_ntp_status(status_out))
        result["configured_servers"] = parse_ntp_associations(assoc_out)

        if expected_servers:
            result["missing_servers"] = set(expected_servers) - result["configured_servers"]

    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed"
    except (paramiko.SSHException, OSError) as exc:
        result["error"] = str(exc)

    return result


def print_report(results, expected_servers):
    width = 62
    print("\n" + "=" * width)
    print(f"{'NTP Status Report':^{width}}")
    print("=" * width)

    for r in results:
        if not r["reachable"]:
            print(f"\n[UNREACHABLE] {r['host']} — {r['error']}")
            continue

        tag = "OK  " if r["synchronized"] else "FAIL"
        stratum = r["stratum"] if r["stratum"] is not None else "?"
        ref = r["reference"] or "?"
        print(f"\n[{tag}] {r['host']}")
        print(f"       State   : {r['clock_state']}")
        print(f"       Stratum : {stratum}")
        print(f"       Ref     : {ref}")
        if r["configured_servers"]:
            print(f"       Servers : {', '.join(sorted(r['configured_servers']))}")
        if r["missing_servers"]:
            print(f"       MISSING : {', '.join(sorted(r['missing_servers']))}")

    print("\n" + "=" * width)
    total = len(results)
    synced = sum(1 for r in results if r["synchronized"])
    print(f"Summary: {synced}/{total} devices synchronized")
    if expected_servers:
        compliant = sum(
            1 for r in results
            if r["reachable"] and r["synchronized"] and not r["missing_servers"]
        )
        print(f"         {compliant}/{total} fully NTP-compliant")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Check NTP synchronization status on Cisco IOS/IOS-XE devices."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--device", help="Device IP or hostname")
    group.add_argument("--host-file", metavar="FILE", help="File with one device per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", dest="key_file", metavar="PATH", help="SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--expected", nargs="+", metavar="IP",
        help="NTP server IPs that must be configured on each device",
    )
    parser.add_argument("--timeout", type=int, default=10, help="SSH connect timeout in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_file:
        password = getpass.getpass(f"Password for {args.username}: ")

    if args.device:
        hosts = [args.device]
    else:
        try:
            with open(args.host_file) as fh:
                hosts = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except OSError as exc:
            log.error("Cannot read host file: %s", exc)
            sys.exit(1)

    if not hosts:
        log.error("No hosts to check.")
        sys.exit(1)

    results = []
    for host in hosts:
        log.info("Checking %s ...", host)
        results.append(
            check_device(host, args.username, password, args.key_file,
                         args.port, args.expected, args.timeout)
        )

    print_report(results, args.expected)

    failures = [
        r for r in results
        if not r["reachable"] or not r["synchronized"] or r.get("missing_servers")
    ]
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()