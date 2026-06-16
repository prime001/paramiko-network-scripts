```python
"""
config_audit.py - Network device configuration compliance auditor.

Connects to a Cisco IOS/IOS-XE device via SSH and validates the running
configuration against user-defined compliance rules: patterns that must be
present (required) and patterns that must be absent (forbidden). Useful for
enforcing security baselines and verifying change-management policies.

Prerequisites:
    pip install paramiko

Usage:
    # Inline rules
    python config_audit.py --host 192.168.1.1 --user admin --password secret \\
        --require "service password-encryption" \\
        --require "logging 10.0.0.1" \\
        --forbid "enable password "

    # Load rules from JSON file
    python config_audit.py --host 192.168.1.1 --user admin --password secret \\
        --rules baseline.json

    # baseline.json format:
    # {"required": ["service password-encryption"], "forbidden": ["enable password"]}

    # Save retrieved config alongside the audit
    python config_audit.py --host 192.168.1.1 --user admin --password secret \\
        --rules baseline.json --save-config running.txt

Exit codes:
    0  All rules passed
    1  One or more rules failed or a runtime error occurred
"""

import argparse
import json
import logging
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_connect(host, port, username, password, timeout):
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


def get_running_config(client):
    chan = client.invoke_shell()
    chan.settimeout(30)
    time.sleep(1)
    chan.recv(65535)

    for cmd in ("terminal length 0\n", "show running-config\n"):
        chan.send(cmd)
        time.sleep(0.5 if "terminal" in cmd else 4)
        if "terminal" in cmd:
            chan.recv(65535)

    output = b""
    deadline = time.time() + 20
    while time.time() < deadline:
        if chan.recv_ready():
            chunk = chan.recv(65535)
            output += chunk
            if b"end" in chunk.lower().splitlines()[-3:]:
                break
        else:
            time.sleep(0.3)

    chan.close()
    return output.decode("utf-8", errors="replace")


def audit_config(config_text, required_patterns, forbidden_patterns):
    text_lower = config_text.lower()
    results = []

    for pattern in required_patterns:
        found = pattern.lower() in text_lower
        results.append({
            "rule_type": "required",
            "pattern": pattern,
            "passed": found,
            "detail": "FOUND" if found else "MISSING",
        })

    for pattern in forbidden_patterns:
        found = pattern.lower() in text_lower
        results.append({
            "rule_type": "forbidden",
            "pattern": pattern,
            "passed": not found,
            "detail": "ABSENT" if not found else "FOUND — violation",
        })

    return results


def print_report(host, results):
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    width = 60
    print(f"\n{'=' * width}")
    print(f"Audit report: {host}   ({passed}/{total} rules passed)")
    print(f"{'=' * width}")
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        tag = "REQ" if r["rule_type"] == "required" else "FBD"
        print(f"  [{status}][{tag}] {r['pattern']!r:<40} {r['detail']}")
    print()
    return passed == total


def parse_args():
    p = argparse.ArgumentParser(
        description="Audit running config against required/forbidden pattern rules."
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--user", required=True, help="SSH username")
    p.add_argument("--password", required=True, help="SSH password")
    p.add_argument("--timeout", type=int, default=30, help="SSH connect timeout (s)")
    p.add_argument(
        "--require",
        metavar="PATTERN",
        action="append",
        default=[],
        help="Pattern that must appear in config (repeatable)",
    )
    p.add_argument(
        "--forbid",
        metavar="PATTERN",
        action="append",
        default=[],
        help="Pattern that must not appear in config (repeatable)",
    )
    p.add_argument(
        "--rules",
        metavar="FILE",
        help='JSON file: {"required": [...], "forbidden": [...]}',
    )
    p.add_argument(
        "--save-config",
        metavar="FILE",
        help="Write retrieved running config to FILE",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    required = list(args.require)
    forbidden = list(args.forbid)

    if args.rules:
        try:
            with open(args.rules) as fh:
                rule_data = json.load(fh)
            required += rule_data.get("required", [])
            forbidden += rule_data.get("forbidden", [])
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Failed to load rules file: %s", exc)
            sys.exit(1)

    if not required and not forbidden:
        log.error("No rules provided. Use --require, --forbid, or --rules.")
        sys.exit(1)

    log.info("Connecting to %s:%d as %s", args.host, args.port, args.user)
    try:
        client = ssh_connect(args.host, args.port, args.user, args.password, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        log.info("Retrieving running configuration")
        config_text = get_running_config(client)
    except Exception as exc:
        log.error("Failed to retrieve config: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    if args.save_config:
        try:
            with open(args.save_config, "w") as fh:
                fh.write(config_text)
            log.info("Config saved to %s", args.save_config)
        except OSError as exc:
            log.warning("Could not save config: %s", exc)

    results = audit_config(config_text, required, forbidden)
    all_passed = print_report(args.host, results)
    sys.exit(0 if all_passed else 1)
```