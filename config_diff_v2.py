config_compliance.py - Network device configuration compliance checker

Connects to a network device via SSH, retrieves the running configuration,
and validates it against a policy file containing required and forbidden patterns.
Exits with code 0 if compliant, 1 if violations found.

Usage:
    python config_compliance.py -d 192.168.1.1 -u admin -p policy.json
    python config_compliance.py -d 192.168.1.1 -u admin --password secret -p policy.json
    python config_compliance.py -d 192.168.1.1 -u admin -p policy.json --output report.txt

Prerequisites:
    pip install paramiko

Policy file format (JSON):
    {
        "required": ["ntp server 10\\.0\\.0\\.1", "service password-encryption", "logging"],
        "forbidden": ["enable password \\S+", "ip telnet"]
    }
    Patterns are Python regexes matched against the full running-config.
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import List

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class ComplianceResult:
    device: str
    passed: List[str] = field(default_factory=list)
    failed_required: List[str] = field(default_factory=list)
    failed_forbidden: List[str] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return not self.failed_required and not self.failed_forbidden


def fetch_running_config(
    host: str, username: str, password: str, port: int = 22, timeout: int = 30
) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
        )
        try:
            _, stdout, _ = client.exec_command("show running-config", timeout=timeout)
            output = stdout.read().decode("utf-8", errors="replace")
            if output.strip():
                return output
        except Exception:
            pass

        shell = client.invoke_shell()
        shell.send("terminal length 0\n")
        time.sleep(1)
        shell.send("show running-config\n")
        time.sleep(timeout / 6)

        chunks = []
        while shell.recv_ready():
            chunks.append(shell.recv(65535).decode("utf-8", errors="replace"))
            time.sleep(0.2)
        return "".join(chunks)
    finally:
        client.close()


def load_policy(policy_path: str) -> dict:
    with open(policy_path) as fh:
        policy = json.load(fh)
    if "required" not in policy and "forbidden" not in policy:
        raise ValueError("Policy must contain 'required' and/or 'forbidden' keys")
    policy.setdefault("required", [])
    policy.setdefault("forbidden", [])
    return policy


def check_compliance(config: str, policy: dict, device: str) -> ComplianceResult:
    result = ComplianceResult(device=device)
    flags = re.IGNORECASE | re.MULTILINE

    for pattern in policy["required"]:
        if re.search(pattern, config, flags):
            result.passed.append(f"[required] {pattern}")
        else:
            result.failed_required.append(f"[required] {pattern}")

    for pattern in policy["forbidden"]:
        if re.search(pattern, config, flags):
            result.failed_forbidden.append(f"[forbidden] {pattern}")
        else:
            result.passed.append(f"[forbidden absent] {pattern}")

    return result


def format_report(result: ComplianceResult) -> str:
    status = "COMPLIANT" if result.compliant else "NON-COMPLIANT"
    lines = [
        f"Compliance Report — {result.device}",
        "=" * 52,
        f"Status: {status}",
        f"Passed: {len(result.passed)}  |  "
        f"Violations: {len(result.failed_required) + len(result.failed_forbidden)}",
        "",
    ]

    if result.failed_required:
        lines.append(f"MISSING required patterns ({len(result.failed_required)}):")
        lines.extend(f"  FAIL  {p}" for p in result.failed_required)
        lines.append("")

    if result.failed_forbidden:
        lines.append(f"FORBIDDEN patterns present ({len(result.failed_forbidden)}):")
        lines.extend(f"  FAIL  {p}" for p in result.failed_forbidden)
        lines.append("")

    if result.passed:
        lines.append(f"Passing checks ({len(result.passed)}):")
        lines.extend(f"  OK    {p}" for p in result.passed)
        lines.append("")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a network device's running config against a compliance policy"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("-p", "--policy", required=True, help="Path to JSON policy file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    parser.add_argument("--output", help="Write report to file instead of stdout")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        paramiko.util.log_to_file("/dev/null")

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    try:
        policy = load_policy(args.policy)
        logger.info(
            "Policy loaded: %d required, %d forbidden patterns",
            len(policy["required"]), len(policy["forbidden"]),
        )
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        logger.error("Policy error: %s", exc)
        sys.exit(1)

    logger.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        config = fetch_running_config(
            args.device, args.username, password,
            port=args.port, timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    if not config.strip():
        logger.error("No configuration returned from %s", args.device)
        sys.exit(1)

    result = check_compliance(config, policy, args.device)
    report = format_report(result)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report)
        logger.info("Report written to %s", args.output)
    else:
        print(report)

    sys.exit(0 if result.compliant else 1)