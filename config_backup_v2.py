```python
"""
config_compliance.py - Network Device Configuration Compliance Checker

Purpose:
    Connects to a network device via SSH (paramiko), retrieves the running
    configuration, and evaluates it against a set of compliance rules defined
    in a JSON policy file. Produces a pass/fail report with line-level evidence.

Usage:
    python config_compliance.py -d 192.168.1.1 -u admin -p secret -P policy.json
    python config_compliance.py -d 10.0.0.1 -u admin --ask-pass -P policy.json --output report.txt

Prerequisites:
    pip install paramiko
    Python 3.8+

Policy file format (JSON):
    {
        "required": ["service password-encryption", "no ip http server"],
        "prohibited": ["telnet", "no service password-encryption"],
        "regex_required": ["logging \\d+\\.\\d+\\.\\d+\\.\\d+"],
        "regex_prohibited": ["enable password (?!7)"]
    }
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

DEFAULT_POLICY = {
    "required": [
        "service password-encryption",
        "no ip http server",
        "no ip http secure-server",
        "logging on",
    ],
    "prohibited": [
        "enable password ",
        "no service password-encryption",
    ],
    "regex_required": [
        r"ntp server \d+\.\d+\.\d+\.\d+",
        r"logging \d+\.\d+\.\d+\.\d+",
    ],
    "regex_prohibited": [
        r"username \S+ password (?!7 )\d",
    ],
}


def fetch_running_config(host, username, password, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        channel = client.invoke_shell()
        time.sleep(1)
        channel.recv(4096)  # discard banner/prompt

        channel.send("terminal length 0\n")
        time.sleep(0.5)
        channel.recv(4096)

        channel.send("show running-config\n")
        time.sleep(3)

        output = ""
        while channel.recv_ready():
            output += channel.recv(65535).decode("utf-8", errors="replace")
            time.sleep(0.2)

        return output
    finally:
        client.close()


def load_policy(policy_path):
    if policy_path:
        with open(policy_path) as f:
            policy = json.load(f)
        log.info("Loaded policy from %s", policy_path)
        return policy
    log.info("Using built-in default policy")
    return DEFAULT_POLICY


def check_compliance(config_text, policy):
    results = []

    for rule in policy.get("required", []):
        passed = rule.lower() in config_text.lower()
        evidence = None
        if passed:
            for line in config_text.splitlines():
                if rule.lower() in line.lower():
                    evidence = line.strip()
                    break
        results.append({
            "type": "required",
            "rule": rule,
            "passed": passed,
            "evidence": evidence,
        })

    for rule in policy.get("prohibited", []):
        matches = [
            line.strip() for line in config_text.splitlines()
            if rule.lower() in line.lower()
        ]
        passed = len(matches) == 0
        results.append({
            "type": "prohibited",
            "rule": rule,
            "passed": passed,
            "evidence": matches[0] if matches else None,
        })

    for pattern in policy.get("regex_required", []):
        match = re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE)
        results.append({
            "type": "regex_required",
            "rule": pattern,
            "passed": match is not None,
            "evidence": match.group(0) if match else None,
        })

    for pattern in policy.get("regex_prohibited", []):
        match = re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE)
        results.append({
            "type": "regex_prohibited",
            "rule": pattern,
            "passed": match is None,
            "evidence": match.group(0) if match else None,
        })

    return results


def format_report(host, results, output_path=None):
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    score = f"{passed}/{total}"

    lines = [
        f"Compliance Report — {host}",
        "=" * 50,
        f"Score: {score} ({100 * passed // total}%)" if total else "Score: N/A",
        "",
    ]

    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        tag = f"[{r['type'].upper()}]"
        lines.append(f"  {status}  {tag} {r['rule']}")
        if not r["passed"] and r["evidence"]:
            lines.append(f"         ^ found: {r['evidence']}")
        elif r["passed"] and r["evidence"]:
            lines.append(f"         ^ matched: {r['evidence']}")

    lines.append("")
    report = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(report)
        log.info("Report saved to %s", output_path)
    else:
        print(report)

    return passed == total


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check network device config against compliance policy"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-P", "--policy", default=None, help="Path to JSON policy file")
    parser.add_argument("-o", "--output", default=None, help="Save report to file")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    password = args.password
    if args.ask_pass or not password:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        policy = load_policy(args.policy)
        log.info("Connecting to %s:%d", args.device, args.port)
        config_text = fetch_running_config(
            args.device, args.username, password, args.port, args.timeout
        )
        results = check_compliance(config_text, policy)
        compliant = format_report(args.device, results, args.output)
        sys.exit(0 if compliant else 1)
    except FileNotFoundError as e:
        log.error("Policy file not found: %s", e)
        sys.exit(2)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(2)
    except paramiko.SSHException as e:
        log.error("SSH error: %s", e)
        sys.exit(2)
    except OSError as e:
        log.error("Connection error: %s", e)
        sys.exit(2)
```