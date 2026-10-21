```python
"""
config_compliance.py - Network Device Configuration Compliance Checker

Purpose:
    Connects to a network device via SSH and validates its running configuration
    against a set of compliance rules (required patterns that must be present,
    forbidden patterns that must not appear). Returns exit code 0 for compliant
    devices and 1 for non-compliant, making it suitable for CI/CD pipelines and
    scheduled audits.

Usage:
    python config_compliance.py -H 192.168.1.1 -u admin -p secret
    python config_compliance.py -H 192.168.1.1 -u admin --ask-pass --rules rules.json
    python config_compliance.py -H 192.168.1.1 -u admin -p secret --output report.txt

Prerequisites:
    pip install paramiko

    Optional rules file (JSON) format:
        {
            "required": ["^ip ssh version 2", "^service password-encryption"],
            "forbidden": ["enable password ", "^no service password-encryption"]
        }
    Patterns are Python regex applied line-by-line against the running config.
    Without --rules, built-in CIS-style baseline checks are used.
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

DEFAULT_RULES = {
    "required": [
        r"^service password-encryption",
        r"^ip ssh version 2",
        r"^no ip http server",
        r"^logging \d+\.\d+\.\d+\.\d+",
        r"^ntp server \S+",
    ],
    "forbidden": [
        r"^enable password \S+",
        r"^ip http server$",
        r"^no service password-encryption",
        r"username \S+ privilege 15 password",
    ],
}


def fetch_running_config(host, username, password, port=22, timeout=30):
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
        shell = client.invoke_shell(width=250, height=250)
        time.sleep(1)
        shell.recv(65535)

        for cmd in ("terminal length 0\n", "show running-config\n"):
            shell.send(cmd)
            time.sleep(2 if "show" in cmd else 0.5)

        output = ""
        deadline = time.time() + 15
        while time.time() < deadline:
            if shell.recv_ready():
                output += shell.recv(65535).decode("utf-8", errors="replace")
            else:
                time.sleep(0.3)
                if not shell.recv_ready():
                    break

        return output
    finally:
        client.close()


def evaluate_rules(config_text, rules):
    findings = {"required": [], "forbidden": [], "compliant": True}

    for pattern in rules.get("required", []):
        hit = bool(re.search(pattern, config_text, re.MULTILINE))
        if not hit:
            findings["compliant"] = False
        findings["required"].append({"pattern": pattern, "pass": hit})

    for pattern in rules.get("forbidden", []):
        hit = bool(re.search(pattern, config_text, re.MULTILINE))
        if hit:
            findings["compliant"] = False
        offenders = [ln.strip() for ln in config_text.splitlines()
                     if re.search(pattern, ln)]
        findings["forbidden"].append({
            "pattern": pattern,
            "pass": not hit,
            "offenders": offenders,
        })

    return findings


def build_report(host, findings):
    sep = "=" * 62
    status = "COMPLIANT" if findings["compliant"] else "NON-COMPLIANT"
    lines = [sep, f"Compliance Report  |  {host}  |  {status}", sep]

    lines.append("\nRequired (must be present):")
    for c in findings["required"]:
        mark = "PASS" if c["pass"] else "FAIL"
        icon = "+" if c["pass"] else "-"
        lines.append(f"  [{icon}] {mark}  {c['pattern']}")

    lines.append("\nForbidden (must be absent):")
    for c in findings["forbidden"]:
        mark = "PASS" if c["pass"] else "FAIL"
        icon = "+" if c["pass"] else "-"
        lines.append(f"  [{icon}] {mark}  {c['pattern']}")
        for ln in c["offenders"]:
            lines.append(f"         found: {ln}")

    total = len(findings["required"]) + len(findings["forbidden"])
    passed = (sum(1 for c in findings["required"] if c["pass"]) +
              sum(1 for c in findings["forbidden"] if c["pass"]))
    lines += [f"\nResult: {passed}/{total} checks passed", sep]
    return "\n".join(lines)


def parse_args():
    p = argparse.ArgumentParser(
        description="Validate a network device's running config against compliance rules"
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password")
    p.add_argument("--ask-pass", action="store_true", help="Prompt for password interactively")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    p.add_argument("--rules", help="JSON file containing required/forbidden patterns")
    p.add_argument("--output", help="Write report to this file instead of stdout")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
    if not password:
        logger.error("A password is required. Use -p or --ask-pass.")
        sys.exit(2)

    rules = DEFAULT_RULES
    if args.rules:
        try:
            with open(args.rules) as fh:
                rules = json.load(fh)
            logger.info("Loaded compliance rules from %s", args.rules)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Could not load rules file: %s", exc)
            sys.exit(2)

    logger.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        config_text = fetch_running_config(
            args.host, args.username, password,
            port=args.port, timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(2)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("SSH connection error: %s", exc)
        sys.exit(2)

    logger.info("Fetched running config (%d chars), evaluating rules…", len(config_text))
    findings = evaluate_rules(config_text, rules)
    report = build_report(args.host, findings)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(report + "\n")
            logger.info("Report saved to %s", args.output)
        except OSError as exc:
            logger.error("Failed to write output file: %s", exc)
            sys.exit(2)
    else:
        print(report)

    sys.exit(0 if findings["compliant"] else 1)
```