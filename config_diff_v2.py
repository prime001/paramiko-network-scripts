```python
"""
config_compliance_audit.py - Network device configuration compliance auditor.

Purpose:
    Connects to a network device via SSH and checks the running configuration
    against user-defined compliance rules (required and forbidden patterns).
    Produces a structured pass/fail report for auditing and remediation workflows.

Usage:
    python config_compliance_audit.py -H 192.168.1.1 -u admin -p secret \\
        --rules rules.json [--output report.txt] [--timeout 30]

Prerequisites:
    pip install paramiko

Rules file format (rules.json):
    {
        "required": ["^service password-encryption", "^logging \\d+\\.\\d+\\.\\d+\\.\\d+"],
        "forbidden": ["^enable password ", "no service password-encryption"]
    }
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import List, Tuple

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class ComplianceResult:
    rule: str
    rule_type: str
    passed: bool
    matched_lines: List[str] = field(default_factory=list)


def fetch_running_config(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 30,
    command: str = "show running-config",
) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logger.info("Connecting to %s:%d", host, port)
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        chan = client.invoke_shell()
        chan.settimeout(timeout)
        time.sleep(1)
        chan.recv(4096)
        chan.send("terminal length 0\n")
        time.sleep(1)
        chan.recv(4096)
        chan.send(f"{command}\n")

        output = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            if chan.recv_ready():
                chunk = chan.recv(8192).decode("utf-8", errors="replace")
                output.append(chunk)
                if re.search(r"#\s*$", chunk.split("\n")[-1]):
                    break
            else:
                time.sleep(0.2)

        return "".join(output)
    finally:
        client.close()


def load_rules(rules_path: str) -> Tuple[List[str], List[str]]:
    with open(rules_path) as f:
        data = json.load(f)
    required = data.get("required", [])
    forbidden = data.get("forbidden", [])
    if not isinstance(required, list) or not isinstance(forbidden, list):
        raise ValueError("Rules file must have 'required' and 'forbidden' as lists")
    return required, forbidden


def audit_config(
    config: str,
    required_patterns: List[str],
    forbidden_patterns: List[str],
) -> List[ComplianceResult]:
    lines = config.splitlines()
    results = []

    for pattern in required_patterns:
        matched = [ln for ln in lines if re.search(pattern, ln)]
        results.append(ComplianceResult(
            rule=pattern,
            rule_type="required",
            passed=bool(matched),
            matched_lines=matched,
        ))

    for pattern in forbidden_patterns:
        matched = [ln for ln in lines if re.search(pattern, ln)]
        results.append(ComplianceResult(
            rule=pattern,
            rule_type="forbidden",
            passed=not matched,
            matched_lines=matched,
        ))

    return results


def format_report(host: str, results: List[ComplianceResult]) -> str:
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    lines = [
        f"Compliance Audit Report: {host}",
        "=" * 60,
        f"Total: {len(results)}  Passed: {passed}  Failed: {failed}",
        "",
    ]
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        lines.append(f"[{status}] [{r.rule_type.upper():8}] {r.rule}")
        if not r.passed and r.matched_lines:
            for ml in r.matched_lines[:3]:
                lines.append(f"           matched: {ml.strip()}")
    lines += ["", f"Result: {'COMPLIANT' if failed == 0 else 'NON-COMPLIANT'}"]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit network device configuration against compliance rules."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--rules", required=True, help="Path to JSON compliance rules file")
    parser.add_argument("--output", help="Write report to file instead of stdout")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds (default: 30)")
    parser.add_argument(
        "--command",
        default="show running-config",
        help="Command to retrieve configuration (default: 'show running-config')",
    )
    parser.add_argument(
        "--fail-on-violations",
        action="store_true",
        help="Exit with code 1 if any rules fail (useful in CI pipelines)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    try:
        required_patterns, forbidden_patterns = load_rules(args.rules)
        logger.info(
            "Loaded %d required and %d forbidden rules",
            len(required_patterns),
            len(forbidden_patterns),
        )
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        logger.error("Failed to load rules file: %s", e)
        sys.exit(2)

    try:
        config = fetch_running_config(
            host=args.host,
            username=args.username,
            password=args.password,
            port=args.port,
            timeout=args.timeout,
            command=args.command,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as e:
        logger.error("Connection error: %s", e)
        sys.exit(1)

    results = audit_config(config, required_patterns, forbidden_patterns)
    report = format_report(args.host, results)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        logger.info("Report written to %s", args.output)
    else:
        print(report)

    failed_count = sum(1 for r in results if not r.passed)
    if args.fail_on_violations and failed_count > 0:
        sys.exit(1)
```