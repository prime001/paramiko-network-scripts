```python
"""config_compliance_checker.py — Network Device Configuration Compliance Auditor

Connects to a Cisco IOS (or compatible) device via SSH and audits its running
configuration against a YAML-defined policy file. Reports each rule as PASS or
FAIL and exits non-zero if any required rule fails.

Usage:
    python config_compliance_checker.py -H 192.168.1.1 -u admin --policy policy.yaml
    python config_compliance_checker.py -H 10.0.0.1 -u admin -p secret \\
        --policy policy.yaml --output report.txt --port 22

Policy file format (YAML):
    rules:
      - name: "NTP server present"
        pattern: "ntp server 10.0.0.1"
        required: true
        description: "Corporate NTP server must be configured"
      - name: "Telnet disabled"
        pattern: "transport input telnet"
        required: false
        description: "Telnet must not appear as an allowed transport"

Prerequisites:
    pip install paramiko pyyaml
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import List

import paramiko
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class ComplianceRule:
    name: str
    pattern: str
    required: bool = True
    description: str = ""


@dataclass
class ComplianceResult:
    rule: ComplianceRule
    passed: bool
    matched_lines: List[str] = field(default_factory=list)


def load_policy(policy_file: str) -> List[ComplianceRule]:
    with open(policy_file) as f:
        data = yaml.safe_load(f)
    return [
        ComplianceRule(
            name=item["name"],
            pattern=item["pattern"],
            required=item.get("required", True),
            description=item.get("description", ""),
        )
        for item in data.get("rules", [])
    ]


def get_running_config(client: paramiko.SSHClient, timeout: int) -> str:
    _, stdout, stderr = client.exec_command("show running-config", timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        logger.warning("Device stderr: %s", err)
    return output


def audit_config(
    config: str, rules: List[ComplianceRule]
) -> List[ComplianceResult]:
    results = []
    for rule in rules:
        matched = [
            line for line in config.splitlines() if re.search(rule.pattern, line)
        ]
        if rule.required:
            passed = len(matched) > 0
        else:
            passed = len(matched) == 0
        results.append(
            ComplianceResult(rule=rule, passed=passed, matched_lines=matched)
        )
    return results


def format_report(host: str, results: List[ComplianceResult]) -> str:
    passed_count = sum(1 for r in results if r.passed)
    total = len(results)
    lines = [
        f"Compliance Report — {host}",
        "=" * 60,
        f"Score: {passed_count}/{total} checks passed",
        "",
    ]
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        lines.append(f"  [{status}] {result.rule.name}")
        if result.rule.description:
            lines.append(f"         {result.rule.description}")
        if not result.passed:
            if result.matched_lines:
                for line in result.matched_lines[:3]:
                    lines.append(f"         Found:   {line.strip()}")
            else:
                lines.append(f"         Missing: pattern '{result.rule.pattern}'")
    lines += [
        "",
        "=" * 60,
        f"Overall: {'COMPLIANT' if passed_count == total else 'NON-COMPLIANT'}",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit a network device's running config against a compliance policy"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument(
        "-p", "--password", help="SSH password (prompted if omitted and no key given)"
    )
    parser.add_argument("--key", help="Path to SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--policy", required=True, help="Path to YAML compliance policy file"
    )
    parser.add_argument("--output", help="Write report to file instead of stdout")
    parser.add_argument(
        "--timeout", type=int, default=30, help="SSH/command timeout seconds (default: 30)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        rules = load_policy(args.policy)
    except FileNotFoundError:
        logger.error("Policy file not found: %s", args.policy)
        sys.exit(1)
    except (KeyError, yaml.YAMLError) as exc:
        logger.error("Invalid policy file: %s", exc)
        sys.exit(1)

    logger.info("Loaded %d rules from %s", len(rules), args.policy)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    config = ""
    try:
        connect_kwargs: dict = {
            "hostname": args.host,
            "port": args.port,
            "username": args.username,
            "timeout": args.timeout,
        }
        if args.key:
            connect_kwargs["key_filename"] = args.key
        else:
            connect_kwargs["password"] = password

        logger.info("Connecting to %s:%d", args.host, args.port)
        client.connect(**connect_kwargs)
        logger.info("Retrieving running configuration")
        config = get_running_config(client, timeout=args.timeout)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        logger.error("SSH error: %s", exc)
        sys.exit(1)
    except OSError as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    if not config.strip():
        logger.error("Empty configuration received — verify device type and credentials")
        sys.exit(1)

    results = audit_config(config, rules)
    report = format_report(args.host, results)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report + "\n")
        logger.info("Report written to %s", args.output)
    else:
        print(report)

    if any(not r.passed for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
```