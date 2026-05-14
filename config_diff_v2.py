config_compliance.py - Network device configuration compliance auditor.

Connects to a network device via SSH, retrieves the running configuration,
and validates it against a YAML compliance policy that defines required
patterns, forbidden patterns, and required configuration sections.

Usage:
    python config_compliance.py -H 192.168.1.1 -u admin -p secret -P policy.yaml
    python config_compliance.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa -P policy.yaml
    python config_compliance.py -H 192.168.1.1 -u admin -p secret -P policy.yaml --output report.txt

Prerequisites:
    pip install paramiko pyyaml

Policy YAML format:
    required:
      - pattern: "service password-encryption"
        description: "Password encryption must be enabled"
      - pattern: "logging \\d+\\.\\d+\\.\\d+\\.\\d+"
        description: "Syslog server must be configured"
    forbidden:
      - pattern: "enable password "
        description: "Must use enable secret, not enable password"
    sections:
      - name: "AAA configuration"
        start: "^aaa new-model"

Exit codes: 0 = all checks passed, 1 = one or more checks failed, 2 = error.
"""

import argparse
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional

import paramiko
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class PolicyResult:
    rule: str
    description: str
    passed: bool
    evidence: str = ""


@dataclass
class ComplianceReport:
    host: str
    timestamp: str
    results: List[PolicyResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)


def connect(host: str, port: int, username: str, password: Optional[str],
            key_path: Optional[str], timeout: int) -> paramiko.SSHClient:
    if not password and not key_path:
        raise ValueError("Either --password or --key must be provided")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username, timeout=timeout,
                  look_for_keys=False, allow_agent=False)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def get_running_config(client: paramiko.SSHClient, timeout: int = 30) -> str:
    shell = client.invoke_shell(width=200, height=5000)
    time.sleep(1)
    shell.recv(65535)

    for cmd in ("terminal length 0\n", "show running-config\n"):
        shell.send(cmd)
        time.sleep(1 if "terminal" in cmd else 2)
        if "terminal" in cmd:
            shell.recv(65535)

    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if re.search(r"#\s*$", chunk.strip()):
                break
        else:
            time.sleep(0.5)

    shell.close()
    return output


def load_policy(path: str) -> dict:
    with open(path) as f:
        policy = yaml.safe_load(f)
    for key in ("required", "forbidden", "sections"):
        policy.setdefault(key, [])
    return policy


def audit_config(config: str, policy: dict) -> List[PolicyResult]:
    results = []
    flags = re.MULTILINE | re.IGNORECASE

    for rule in policy["required"]:
        pattern = rule["pattern"]
        desc = rule.get("description", pattern)
        match = re.search(pattern, config, flags)
        results.append(PolicyResult(
            rule=f"REQUIRED: {pattern}",
            description=desc,
            passed=bool(match),
            evidence=match.group(0).strip() if match else "(not found)",
        ))

    for rule in policy["forbidden"]:
        pattern = rule["pattern"]
        desc = rule.get("description", pattern)
        match = re.search(pattern, config, flags)
        results.append(PolicyResult(
            rule=f"FORBIDDEN: {pattern}",
            description=desc,
            passed=not bool(match),
            evidence=match.group(0).strip() if match else "(not present)",
        ))

    for section in policy["sections"]:
        name = section["name"]
        match = re.search(section["start"], config, flags)
        results.append(PolicyResult(
            rule=f"SECTION: {section['start']}",
            description=f"Section '{name}' must be present",
            passed=bool(match),
            evidence=match.group(0).strip() if match else "(section not found)",
        ))

    return results


def render_report(report: ComplianceReport) -> str:
    sep = "=" * 60
    overall = "PASS" if report.passed else "FAIL"
    lines = [
        sep,
        f"Compliance Report: {report.host}",
        f"Timestamp:         {report.timestamp}",
        f"Result:            {overall}",
        f"Checks:            {report.pass_count} passed, {report.fail_count} failed",
        sep,
    ]
    for r in report.results:
        status = "PASS" if r.passed else "FAIL"
        lines.append(f"\n[{status}] {r.description}")
        lines.append(f"       Rule:     {r.rule}")
        lines.append(f"       Evidence: {r.evidence}")
    lines.append(f"\n{sep}")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit a network device configuration against a compliance policy"
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_path", default=None,
                        help="Path to SSH private key")
    parser.add_argument("-P", "--policy", required=True,
                        help="Path to YAML compliance policy file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Connection/collection timeout in seconds")
    parser.add_argument("--output", default=None,
                        help="Write report to this file instead of stdout")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    log.info("Loading policy from %s", args.policy)
    try:
        policy = load_policy(args.policy)
    except (FileNotFoundError, yaml.YAMLError) as exc:
        log.error("Failed to load policy: %s", exc)
        sys.exit(2)

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = connect(args.host, args.port, args.username,
                         args.password, args.key_path, args.timeout)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(2)

    try:
        log.info("Retrieving running configuration")
        config = get_running_config(client, args.timeout)
    except Exception as exc:
        log.error("Failed to retrieve config: %s", exc)
        sys.exit(2)
    finally:
        client.close()

    log.info("Auditing configuration (%d bytes)", len(config))
    results = audit_config(config, policy)

    report = ComplianceReport(
        host=args.host,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        results=results,
    )
    output = render_report(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        log.info("Report written to %s", args.output)
    else:
        print(output)

    sys.exit(0 if report.passed else 1)