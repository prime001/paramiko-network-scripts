```python
"""
config_section_audit.py - Network Device Configuration Section Auditor

Purpose:
    Connects to a network device via SSH and audits specific configuration
    sections against a local golden template. Reports missing, extra, and
    matching lines per section, enabling rapid compliance validation without
    a full config diff.

Usage:
    python config_section_audit.py -d 192.168.1.1 -u admin -p secret \\
        -t golden_template.txt --sections ntp,snmp,logging

    python config_section_audit.py -d 10.0.0.1 -u admin --key ~/.ssh/id_rsa \\
        -t golden_template.txt --sections aaa --output report.json

Prerequisites:
    pip install paramiko
    Golden template file: plain-text Cisco IOS config lines (one per line).
    Section headers use Cisco-style keywords (e.g., "ntp", "snmp-server", "logging").
"""

import argparse
import getpass
import json
import logging
import sys
import time
from collections import defaultdict

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    if key_file:
        connect_kwargs["key_filename"] = key_file
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def fetch_running_config(client):
    channel = client.invoke_shell()
    channel.settimeout(30)
    time.sleep(1)
    channel.recv(4096)
    channel.send("terminal length 0\n")
    time.sleep(0.5)
    channel.recv(4096)
    channel.send("show running-config\n")
    time.sleep(3)
    output = b""
    while channel.recv_ready():
        output += channel.recv(65535)
        time.sleep(0.3)
    channel.close()
    return output.decode("utf-8", errors="replace")


def extract_sections(config_text, section_keywords):
    """
    Extract lines belonging to each section keyword from config text.
    Returns dict mapping keyword -> set of config lines in that section.
    """
    sections = defaultdict(set)
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        for keyword in section_keywords:
            if stripped.lower().startswith(keyword.lower()):
                sections[keyword].add(stripped)
                break
    return sections


def load_template_sections(template_path, section_keywords):
    try:
        with open(template_path, "r") as f:
            content = f.read()
    except OSError as e:
        log.error("Cannot read template file %s: %s", template_path, e)
        sys.exit(1)
    return extract_sections(content, section_keywords)


def audit_sections(device_sections, template_sections, section_keywords):
    results = {}
    for keyword in section_keywords:
        device_lines = device_sections.get(keyword, set())
        required_lines = template_sections.get(keyword, set())
        missing = sorted(required_lines - device_lines)
        extra = sorted(device_lines - required_lines)
        matching = sorted(device_lines & required_lines)
        compliant = len(missing) == 0
        results[keyword] = {
            "compliant": compliant,
            "matching": matching,
            "missing": missing,
            "extra": extra,
        }
    return results


def print_audit_report(host, results):
    print(f"\n{'='*60}")
    print(f"Config Section Audit Report: {host}")
    print(f"{'='*60}")
    for section, data in results.items():
        status = "PASS" if data["compliant"] else "FAIL"
        print(f"\n[{status}] Section: {section}")
        if data["matching"]:
            for line in data["matching"]:
                print(f"  OK  {line}")
        if data["missing"]:
            for line in data["missing"]:
                print(f"  MISSING  {line}")
        if data["extra"]:
            for line in data["extra"]:
                print(f"  EXTRA    {line}")
    total = len(results)
    passed = sum(1 for d in results.values() if d["compliant"])
    print(f"\nSummary: {passed}/{total} sections compliant")
    print(f"{'='*60}\n")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Audit network device config sections against a golden template"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("-k", "--key", dest="key_file", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-t", "--template", required=True, help="Path to golden template config file")
    parser.add_argument(
        "--sections",
        required=True,
        help="Comma-separated section keywords to audit (e.g. ntp,snmp-server,logging)",
    )
    parser.add_argument("-o", "--output", default=None, help="Write JSON report to this file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if not args.key_file and args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    section_keywords = [s.strip() for s in args.sections.split(",") if s.strip()]
    if not section_keywords:
        log.error("No valid section keywords provided.")
        sys.exit(1)

    log.info("Loading template from %s", args.template)
    template_sections = load_template_sections(args.template, section_keywords)

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(
            host=args.device,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as e:
        log.error("Connection failed: %s", e)
        sys.exit(1)

    try:
        log.info("Fetching running configuration")
        running_config = fetch_running_config(client)
    finally:
        client.close()

    device_sections = extract_sections(running_config, section_keywords)
    results = audit_sections(device_sections, template_sections, section_keywords)

    print_audit_report(args.device, results)

    if args.output:
        report = {"device": args.device, "sections": results}
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        log.info("JSON report written to %s", args.output)

    any_fail = any(not d["compliant"] for d in results.values())
    sys.exit(1 if any_fail else 0)
```