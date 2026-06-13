```python
"""
config_compliance.py - Network Device Configuration Compliance Auditor

Purpose:
    Connects to a network device via SSH and validates the running configuration
    against a set of required and forbidden patterns. Produces a scored compliance
    report that identifies policy violations and missing controls.

    Distinct from config_diff.py (which compares two config snapshots line-by-line).
    This script validates a live config against declarative policy rules.

Usage:
    python config_compliance.py -H 192.168.1.1 -u admin -p secret
    python config_compliance.py -H 10.0.0.1 -u admin -k ~/.ssh/id_rsa -r rules.json
    python config_compliance.py -H 10.0.0.1 -u admin -p secret -o report.txt --strict

Prerequisites:
    pip install paramiko

Rules file format (JSON):
    {
        "required": [
            {"pattern": "service password-encryption", "description": "Password encryption on"}
        ],
        "forbidden": [
            {"pattern": "transport input telnet$", "description": "Telnet allowed on VTY"}
        ]
    }
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

DEFAULT_RULES = {
    "required": [
        {"pattern": r"service password-encryption", "description": "Password encryption enabled"},
        {"pattern": r"ntp server \S+", "description": "NTP server configured"},
        {"pattern": r"logging \d+\.\d+\.\d+\.\d+", "description": "Remote syslog configured"},
        {"pattern": r"no ip http server", "description": "HTTP server disabled"},
        {"pattern": r"banner (motd|login)", "description": "Login banner configured"},
        {"pattern": r"ip ssh version 2", "description": "SSHv2 enforced"},
    ],
    "forbidden": [
        {"pattern": r"^enable password\b", "description": "Weak enable password (not secret)"},
        {"pattern": r"transport input telnet$", "description": "Telnet allowed on VTY line"},
        {"pattern": r"no service password-encryption", "description": "Password encryption disabled"},
        {"pattern": r"^ip http server$", "description": "Unencrypted HTTP server enabled"},
        {"pattern": r"snmp-server community \S+ RW", "description": "SNMP read-write community"},
    ],
}


def load_rules(path):
    with open(path) as f:
        return json.load(f)


def fetch_running_config(host, username, password=None, key_file=None, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_file),
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Either --password or --key-file is required")

    client.connect(**kwargs)
    logger.info("Connected to %s:%d", host, port)
    try:
        _, stdout, stderr = client.exec_command("show running-config", timeout=60)
        config = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            logger.warning("Device stderr: %s", err)
        return config
    finally:
        client.close()


def audit_config(config, rules):
    lines = config.splitlines()
    findings = {"required": [], "forbidden": [], "passed": 0, "failed": 0}

    for rule in rules.get("required", []):
        matched = any(re.search(rule["pattern"], line) for line in lines)
        findings["required"].append({
            "description": rule["description"],
            "pattern": rule["pattern"],
            "status": "PASS" if matched else "FAIL",
        })
        findings["passed" if matched else "failed"] += 1

    for rule in rules.get("forbidden", []):
        hits = [line.strip() for line in lines if re.search(rule["pattern"], line)]
        findings["forbidden"].append({
            "description": rule["description"],
            "pattern": rule["pattern"],
            "status": "FAIL" if hits else "PASS",
            "matches": hits,
        })
        findings["passed" if not hits else "failed"] += 1

    total = findings["passed"] + findings["failed"]
    findings["score"] = round(findings["passed"] / total * 100, 1) if total else 0.0
    findings["total"] = total
    return findings


def render_report(host, findings, timestamp):
    score = findings["score"]
    verdict = "COMPLIANT" if findings["failed"] == 0 else "NON-COMPLIANT"
    lines = [
        "Config Compliance Report",
        "=" * 40,
        f"Host      : {host}",
        f"Timestamp : {timestamp}",
        f"Score     : {score}% ({findings['passed']}/{findings['total']} checks passed)",
        f"Verdict   : {verdict}",
        "",
        "Required Controls",
        "-" * 40,
    ]
    for item in findings["required"]:
        tag = "PASS" if item["status"] == "PASS" else "FAIL"
        lines.append(f"  [{tag}] {item['description']}")
        if item["status"] == "FAIL":
            lines.append(f"         missing: {item['pattern']}")

    lines += ["", "Forbidden Controls", "-" * 40]
    for item in findings["forbidden"]:
        tag = "PASS" if item["status"] == "PASS" else "FAIL"
        lines.append(f"  [{tag}] {item['description']}")
        for match in item.get("matches", []):
            lines.append(f"         found: {match}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Audit device config against compliance rules")
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password")
    parser.add_argument("-k", "--key-file", dest="key_file", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-r", "--rules", help="JSON rules file (built-in defaults if omitted)")
    parser.add_argument("-o", "--output", help="Write report to this file instead of stdout")
    parser.add_argument(
        "--strict", action="store_true", help="Exit 1 if device is non-compliant"
    )
    args = parser.parse_args()

    if not args.password and not args.key_file:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    rules = load_rules(args.rules) if args.rules else DEFAULT_RULES

    try:
        config = fetch_running_config(
            host=args.host,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    findings = audit_config(config, rules)
    report = render_report(args.host, findings, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if args.output:
        with open(args.output, "w") as f:
            f.write(report + "\n")
        logger.info("Report written to %s", args.output)
    else:
        print(report)

    if args.strict and findings["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
```