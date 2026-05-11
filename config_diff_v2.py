```python
"""config_audit.py — Network Device Configuration Compliance Auditor

Purpose:
    Connect to a network device via SSH, retrieve the running configuration,
    and evaluate it against a YAML compliance policy that defines required
    and prohibited configuration patterns.  Outputs a severity-grouped report
    suitable for automated pipelines or human review.

Usage:
    python config_audit.py -d 192.168.1.1 -u admin -p secret -c policy.yaml
    python config_audit.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa \
        -c policy.yaml --output report.txt --fail-on-findings

Prerequisites:
    pip install paramiko pyyaml

Policy file (YAML):
    required:
      - pattern: "service password-encryption"
        description: "Passwords must be encrypted"
        severity: HIGH
      - pattern: "logging \\d+\\.\\d+\\.\\d+\\.\\d+"
        description: "Remote syslog server required"
        severity: CRITICAL
    prohibited:
      - pattern: "^username .+ privilege 15 password 0"
        description: "Cleartext privilege-15 passwords forbidden"
        severity: CRITICAL
      - pattern: "ip http server$"
        description: "Unencrypted HTTP management must be disabled"
        severity: HIGH
"""

import argparse
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import paramiko
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class PolicyRule:
    pattern: str
    description: str
    severity: str = "HIGH"


@dataclass
class CompliancePolicy:
    required: list = field(default_factory=list)
    prohibited: list = field(default_factory=list)


@dataclass
class AuditFinding:
    rule_type: str
    description: str
    pattern: str
    severity: str
    matched_lines: list = field(default_factory=list)


def load_policy(policy_path: str) -> CompliancePolicy:
    with open(policy_path) as fh:
        data = yaml.safe_load(fh)
    policy = CompliancePolicy()
    for item in data.get("required", []):
        policy.required.append(PolicyRule(
            pattern=item["pattern"],
            description=item["description"],
            severity=item.get("severity", "HIGH").upper(),
        ))
    for item in data.get("prohibited", []):
        policy.prohibited.append(PolicyRule(
            pattern=item["pattern"],
            description=item["description"],
            severity=item.get("severity", "HIGH").upper(),
        ))
    return policy


def fetch_running_config(host: str, port: int, username: str,
                         password: Optional[str], key_path: Optional[str],
                         timeout: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username,
                  timeout=timeout, look_for_keys=False, allow_agent=False)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password

    try:
        client.connect(**kwargs)
        log.info("Connected to %s:%d", host, port)
        shell = client.invoke_shell()
        shell.settimeout(timeout)
        time.sleep(1)
        shell.recv(4096)
        shell.send("terminal length 0\n")
        time.sleep(0.5)
        shell.recv(4096)
        shell.send("show running-config\n")
        time.sleep(4)
        buf = b""
        while shell.recv_ready():
            buf += shell.recv(65535)
            time.sleep(0.2)
        return buf.decode("utf-8", errors="replace")
    finally:
        client.close()


def audit(config: str, policy: CompliancePolicy) -> list:
    lines = config.splitlines()
    findings = []
    for rule in policy.required:
        hits = [ln for ln in lines if re.search(rule.pattern, ln)]
        if not hits:
            findings.append(AuditFinding(
                rule_type="required", description=rule.description,
                pattern=rule.pattern, severity=rule.severity,
            ))
    for rule in policy.prohibited:
        hits = [ln for ln in lines if re.search(rule.pattern, ln)]
        if hits:
            findings.append(AuditFinding(
                rule_type="prohibited", description=rule.description,
                pattern=rule.pattern, severity=rule.severity,
                matched_lines=hits,
            ))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


def build_report(host: str, findings: list) -> str:
    sep = "=" * 62
    lines = [sep, f"Config Compliance Audit — {host}", sep,
             f"Findings: {len(findings)}", ""]
    if not findings:
        lines.append("PASS — no compliance violations detected.")
        return "\n".join(lines)

    current_sev = None
    for f in findings:
        if f.severity != current_sev:
            current_sev = f.severity
            lines.append(f"[{current_sev}]")
        tag = "MISSING" if f.rule_type == "required" else "VIOLATION"
        lines.append(f"  [{tag}] {f.description}")
        lines.append(f"          pattern : {f.pattern}")
        for ml in f.matched_lines[:3]:
            lines.append(f"          found   : {ml.strip()}")
        lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit a device's running-config against a compliance policy"
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--key", metavar="FILE", help="SSH private key file")
    p.add_argument("-c", "--policy", required=True, help="YAML compliance policy")
    p.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds")
    p.add_argument("--output", metavar="FILE", help="Write report to file")
    p.add_argument("--fail-on-findings", action="store_true",
                   help="Exit 1 if any violations found (CI-friendly)")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if not args.password and not args.key:
        log.error("Provide --password or --key")
        return 2
    if not Path(args.policy).exists():
        log.error("Policy file not found: %s", args.policy)
        return 2

    try:
        policy = load_policy(args.policy)
    except (yaml.YAMLError, KeyError) as exc:
        log.error("Policy parse error: %s", exc)
        return 2

    log.info("Policy: %d required, %d prohibited rules",
             len(policy.required), len(policy.prohibited))

    try:
        config = fetch_running_config(
            host=args.device, port=args.port, username=args.username,
            password=args.password, key_path=args.key, timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    findings = audit(config, policy)
    report = build_report(args.device, findings)

    if args.output:
        Path(args.output).write_text(report)
        log.info("Report saved to %s", args.output)
    else:
        print(report)

    return 1 if (args.fail_on_findings and findings) else 0


if __name__ == "__main__":
    sys.exit(main())
```