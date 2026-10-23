```python
"""
Network Device Configuration Compliance Auditor

Purpose:
    Connects to a network device via SSH, retrieves the running configuration,
    and checks it against a JSON policy file containing must-have and must-not-have
    patterns. Exits non-zero when violations are found, suitable for CI pipelines.

Usage:
    python config_compliance.py -H 192.168.1.1 -u admin -P policy.json
    python config_compliance.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa -P policy.json -o report.txt

Prerequisites:
    pip install paramiko

Policy file format (JSON):
    {
        "must_contain": [
            {"pattern": "ntp server", "description": "NTP server required"},
            {"pattern": "service password-encryption", "description": "Encryption required"}
        ],
        "must_not_contain": [
            {"pattern": "^\\s*service telnet", "description": "Telnet must be disabled"},
            {"pattern": "enable password ", "description": "Must use enable secret, not password"}
        ]
    }
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime
from getpass import getpass
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def load_policy(policy_path: str) -> dict:
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")
    with open(path) as f:
        policy = json.load(f)
    policy.setdefault("must_contain", [])
    policy.setdefault("must_not_contain", [])
    return policy


def fetch_running_config(
    host: str,
    port: int,
    username: str,
    password: str = None,
    key_path: str = None,
    timeout: int = 30,
) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        connect_kwargs["key_filename"] = key_path
    else:
        connect_kwargs["password"] = password

    try:
        log.info("Connecting to %s:%d as %s", host, port, username)
        client.connect(**connect_kwargs)
        _, stdout, stderr = client.exec_command("show running-config", timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.warning("Device stderr: %s", err)
        if not output.strip():
            raise RuntimeError("Empty response from device — check command authorization")
        return output
    finally:
        client.close()


def audit_config(config: str, policy: dict) -> list[dict]:
    violations = []

    for rule in policy["must_contain"]:
        if not re.search(rule["pattern"], config, re.MULTILINE | re.IGNORECASE):
            violations.append({
                "type": "MISSING",
                "pattern": rule["pattern"],
                "description": rule.get("description", rule["pattern"]),
            })

    for rule in policy["must_not_contain"]:
        if re.search(rule["pattern"], config, re.MULTILINE | re.IGNORECASE):
            violations.append({
                "type": "FORBIDDEN",
                "pattern": rule["pattern"],
                "description": rule.get("description", rule["pattern"]),
            })

    return violations


def format_report(host: str, violations: list[dict]) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "Configuration Compliance Report",
        f"Device : {host}",
        f"Checked: {timestamp}",
        "=" * 60,
    ]
    if not violations:
        lines.append("RESULT: COMPLIANT — no violations found")
    else:
        lines.append(f"RESULT: NON-COMPLIANT — {len(violations)} violation(s)\n")
        for i, v in enumerate(violations, 1):
            lines.append(f"  [{i}] {v['type']}: {v['description']}")
            lines.append(f"       Pattern: {v['pattern']}")
    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Audit a network device running-config against a compliance policy."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted and no key)")
    parser.add_argument("--key", dest="key_path", help="Path to SSH private key file")
    parser.add_argument("-P", "--policy", required=True, help="Path to JSON policy file")
    parser.add_argument("-o", "--output", help="Write compliance report to this file")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not args.key_path and not password:
        password = getpass(f"SSH password for {args.username}@{args.host}: ")

    try:
        policy = load_policy(args.policy)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        log.error("Policy load failed: %s", exc)
        sys.exit(2)

    log.info(
        "Policy: %d must_contain, %d must_not_contain rules",
        len(policy["must_contain"]),
        len(policy["must_not_contain"]),
    )

    try:
        config = fetch_running_config(
            host=args.host,
            port=args.port,
            username=args.username,
            password=password,
            key_path=args.key_path,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(2)
    except (paramiko.SSHException, OSError, RuntimeError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(2)

    violations = audit_config(config, policy)
    report = format_report(args.host, violations)
    print(report)

    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        log.info("Report written to %s", args.output)

    sys.exit(1 if violations else 0)


if __name__ == "__main__":
    main()
```