config_compliance.py — Network Device Configuration Compliance Checker

Connects to a network device via SSH, retrieves the running configuration,
and checks it against a set of required configuration patterns loaded from
a compliance rules file. Reports which rules pass, fail, or are missing.

Usage:
    python config_compliance.py -H 192.168.1.1 -u admin -p secret -r rules.txt
    python config_compliance.py -H 10.0.0.1 -u admin -k ~/.ssh/id_rsa -r rules.txt --output report.txt

Prerequisites:
    pip install paramiko
    Rules file: one regex pattern per line; lines starting with # are comments.
    Device must have SSH enabled and the user needs privilege level to run
    'show running-config' (or equivalent for your platform).
"""

import argparse
import logging
import re
import sys
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def load_rules(rules_path: str) -> list[tuple[str, re.Pattern]]:
    rules = []
    with open(rules_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rules.append((line, re.compile(line, re.IGNORECASE | re.MULTILINE)))
            except re.error as e:
                log.warning("Skipping invalid regex %r: %s", line, e)
    return rules


def fetch_running_config(host: str, port: int, username: str,
                         password: str | None, key_path: str | None,
                         timeout: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = dict(
            hostname=host,
            port=port,
            username=username,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        if key_path:
            connect_kwargs["key_filename"] = key_path
            connect_kwargs["look_for_keys"] = False
        else:
            connect_kwargs["password"] = password

        log.info("Connecting to %s:%d", host, port)
        client.connect(**connect_kwargs)

        stdin, stdout, stderr = client.exec_command(
            "show running-config", timeout=timeout
        )
        config = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.warning("stderr from device: %s", err)
        return config
    finally:
        client.close()


def check_compliance(config: str, rules: list[tuple[str, re.Pattern]]) -> list[dict]:
    results = []
    for pattern_str, pattern in rules:
        match = pattern.search(config)
        results.append({
            "pattern": pattern_str,
            "status": "PASS" if match else "FAIL",
            "match": match.group(0).strip() if match else None,
        })
    return results


def format_report(host: str, results: list[dict]) -> str:
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = len(results) - passed
    lines = [
        f"Compliance Report — {host}",
        f"{'=' * 50}",
        f"Total rules: {len(results)}  PASS: {passed}  FAIL: {failed}",
        "",
    ]
    for r in results:
        status = r["status"]
        lines.append(f"[{status}] {r['pattern']}")
        if r["match"]:
            lines.append(f"       matched: {r['match']!r}")
    lines.append("")
    lines.append(f"Score: {passed}/{len(results)} ({100 * passed // len(results)}%)" if results else "No rules evaluated.")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check network device config against compliance rules."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("-k", "--key", default=None, help="Path to SSH private key")
    parser.add_argument("-r", "--rules", required=True, help="Path to compliance rules file")
    parser.add_argument("-o", "--output", default=None, help="Write report to file instead of stdout")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="SSH timeout seconds (default: 30)")
    parser.add_argument("--fail-exit", action="store_true",
                        help="Exit with code 1 if any rule fails")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.password and not args.key:
        log.error("Provide either --password or --key for authentication.")
        return 2

    rules_path = Path(args.rules)
    if not rules_path.exists():
        log.error("Rules file not found: %s", args.rules)
        return 2

    try:
        rules = load_rules(args.rules)
    except OSError as e:
        log.error("Cannot read rules file: %s", e)
        return 2

    if not rules:
        log.error("No valid rules found in %s", args.rules)
        return 2

    log.info("Loaded %d compliance rules", len(rules))

    try:
        config = fetch_running_config(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            key_path=args.key,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as e:
        log.error("Connection error: %s", e)
        return 1

    results = check_compliance(config, rules)
    report = format_report(args.host, results)

    if args.output:
        Path(args.output).write_text(report + "\n")
        log.info("Report written to %s", args.output)
    else:
        print(report)

    failed = sum(1 for r in results if r["status"] == "FAIL")
    if args.fail_exit and failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())