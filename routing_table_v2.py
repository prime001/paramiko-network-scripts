```python
"""
Route Prefix Verifier — validates expected prefixes in a device's routing table.

Purpose:
    Connects to a network device via SSH and verifies that a specified set of
    IP prefixes are present in the routing table, optionally asserting next-hop
    and routing protocol. Useful for post-change validation and compliance audits.

Usage:
    python routing_table_verify.py -d 192.168.1.1 -u admin \
        --prefixes 10.0.0.0/8 172.16.0.0/12 \
        --expected-nexthop 192.168.1.254 \
        --expected-protocol B

    # Load prefixes from a file (one per line):
    python routing_table_verify.py -d 192.168.1.1 -u admin \
        --prefix-file critical_routes.txt -v

Prerequisites:
    pip install paramiko
    Device must have SSH enabled with privilege to run 'show ip route <prefix>'.
    Tested against Cisco IOS, IOS-XE. Adapt verify_prefix() for other NOS.
"""

import argparse
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


def ssh_connect(host, username, password, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as exc:
        log.error("SSH error connecting to %s: %s", host, exc)
        raise


def run_command(client, command, timeout=10):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr for '%s': %s", command, err)
    return output


def verify_prefix(client, prefix, expected_nexthop=None, expected_protocol=None):
    """Check a single prefix; returns a result dict with presence and parsed attributes."""
    output = run_command(client, f"show ip route {prefix}")

    result = {
        "prefix": prefix,
        "present": False,
        "protocol": None,
        "nexthop": None,
        "nexthop_match": None,
        "protocol_match": None,
        "raw": output.strip(),
    }

    not_found_patterns = [
        r"% Network not in table",
        r"% Subnet not in table",
        r"not in table",
        r"not found",
    ]
    for pat in not_found_patterns:
        if re.search(pat, output, re.IGNORECASE):
            return result

    nexthop_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", output)
    if nexthop_match:
        result["present"] = True
        result["nexthop"] = nexthop_match.group(1)

    # IOS protocol codes: B=BGP, O=OSPF, S=Static, C=Connected, R=RIP, E=EIGRP
    proto_match = re.search(r"^\s*([BOSDRCEIL*]+)\s+", output, re.MULTILINE)
    if proto_match:
        result["present"] = True
        result["protocol"] = proto_match.group(1).strip("* ")

    if expected_nexthop and result["nexthop"]:
        result["nexthop_match"] = result["nexthop"] == expected_nexthop

    if expected_protocol and result["protocol"]:
        result["protocol_match"] = expected_protocol.upper() in result["protocol"].upper()

    return result


def print_results(results, verbose=False):
    passed = sum(1 for r in results if r["present"])
    failed = len(results) - passed

    print(f"\n{'='*60}")
    print(f"Route Verification: {passed} present, {failed} missing")
    print(f"{'='*60}")

    for r in results:
        status = "PASS" if r["present"] else "FAIL"
        line = f"[{status}] {r['prefix']}"
        if r["present"]:
            line += f"  proto={r['protocol'] or '?'}  via={r['nexthop'] or '?'}"
            if r["nexthop_match"] is not None:
                line += f"  nexthop={'OK' if r['nexthop_match'] else 'MISMATCH'}"
            if r["protocol_match"] is not None:
                line += f"  protocol={'OK' if r['protocol_match'] else 'MISMATCH'}"
        print(line)
        if verbose and r["raw"]:
            for raw_line in r["raw"].splitlines():
                print(f"    {raw_line}")

    print()
    return failed == 0


def main():
    parser = argparse.ArgumentParser(
        description="Verify that expected IP prefixes are present in a device's routing table."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--prefixes",
        nargs="+",
        default=[],
        metavar="PREFIX",
        help="IP prefixes to verify (e.g. 10.0.0.0/8 192.168.1.0/24)",
    )
    parser.add_argument(
        "--prefix-file",
        metavar="FILE",
        help="File with one prefix per line, merged with --prefixes",
    )
    parser.add_argument(
        "--expected-nexthop",
        metavar="IP",
        help="Assert all matched prefixes resolve via this next-hop IP",
    )
    parser.add_argument(
        "--expected-protocol",
        metavar="PROTO",
        help="Assert routing protocol code (e.g. B, O, S, C, R)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Print raw device output per prefix"
    )
    parser.add_argument("--timeout", type=int, default=15, help="SSH timeout in seconds")
    args = parser.parse_args()

    if not args.prefixes and not args.prefix_file:
        parser.error("Provide at least one prefix via --prefixes or --prefix-file")

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    prefixes = list(args.prefixes)
    if args.prefix_file:
        try:
            with open(args.prefix_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        prefixes.append(line)
        except OSError as exc:
            log.error("Cannot read prefix file: %s", exc)
            sys.exit(1)

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(args.device, args.username, password, args.port, args.timeout)
    except Exception:
        sys.exit(1)

    results = []
    try:
        for prefix in prefixes:
            log.info("Checking %s", prefix)
            result = verify_prefix(
                client,
                prefix,
                expected_nexthop=args.expected_nexthop,
                expected_protocol=args.expected_protocol,
            )
            results.append(result)
    finally:
        client.close()

    all_passed = print_results(results, verbose=args.verbose)
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
```