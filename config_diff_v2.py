```python
"""
config_compliance_diff.py - Golden Config Compliance Checker

Fetches a device's running configuration via SSH and compares it against a
local golden/baseline config file, reporting deviations as a unified diff.

Usage:
    python config_compliance_diff.py -d 192.168.1.1 -u admin -p secret \\
        --golden baseline_router.cfg

    python config_compliance_diff.py -d 10.0.0.1 -u admin --key ~/.ssh/id_rsa \\
        --golden golden.cfg --section "^ip route" --output report.diff

Prerequisites:
    pip install paramiko
    A golden/baseline config file on the local filesystem.
"""

import argparse
import logging
import re
import sys
from difflib import unified_diff
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def fetch_running_config(host, port, username, password, key_path, timeout):
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
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
        log.info("Connected to %s:%d", host, port)
        _, stdout, stderr = client.exec_command(
            "show running-config", timeout=timeout
        )
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.warning("stderr: %s", err)
        return output
    finally:
        client.close()


def normalize_config(text, ignore_patterns):
    lines = []
    for line in text.splitlines():
        if any(re.search(pat, line) for pat in ignore_patterns):
            continue
        lines.append(line.rstrip())
    return lines


def filter_section(lines, section_pattern):
    if not section_pattern:
        return lines
    filtered, in_section = [], False
    for line in lines:
        if re.match(section_pattern, line):
            in_section = True
        elif in_section and line and not line[0].isspace():
            in_section = False
        if in_section:
            filtered.append(line)
    return filtered


def run_diff(golden_lines, running_lines, fromfile, tofile, context):
    diff = list(
        unified_diff(
            golden_lines,
            running_lines,
            fromfile=fromfile,
            tofile=tofile,
            lineterm="",
            n=context,
        )
    )
    return diff


def summarize(diff_lines):
    added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
    return added, removed


def main():
    parser = argparse.ArgumentParser(description="Compare running config to golden baseline")
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    parser.add_argument("-g", "--golden", required=True, help="Path to golden config file")
    parser.add_argument("--section", default=None, help="Regex to filter a specific config section")
    parser.add_argument(
        "--ignore",
        nargs="*",
        default=["^!", "^Building configuration", "^Current configuration"],
        help="Line patterns to ignore (regex)",
    )
    parser.add_argument("--context", type=int, default=3, help="Diff context lines")
    parser.add_argument("-o", "--output", default=None, help="Write diff to file instead of stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    golden_path = Path(args.golden)
    if not golden_path.exists():
        log.error("Golden config not found: %s", args.golden)
        sys.exit(1)

    golden_raw = golden_path.read_text(errors="replace")

    log.info("Fetching running config from %s", args.device)
    try:
        running_raw = fetch_running_config(
            args.device, args.port, args.username, args.password, args.key, args.timeout
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    golden_lines = normalize_config(golden_raw, args.ignore)
    running_lines = normalize_config(running_raw, args.ignore)

    if args.section:
        golden_lines = filter_section(golden_lines, args.section)
        running_lines = filter_section(running_lines, args.section)
        log.debug("Section filter '%s': golden=%d lines, running=%d lines",
                  args.section, len(golden_lines), len(running_lines))

    diff = run_diff(
        golden_lines, running_lines,
        fromfile=f"golden:{args.golden}",
        tofile=f"running:{args.device}",
        context=args.context,
    )

    added, removed = summarize(diff)

    if not diff:
        log.info("COMPLIANT — running config matches golden baseline")
        sys.exit(0)

    log.warning("NON-COMPLIANT — %d line(s) added, %d line(s) removed vs golden", added, removed)

    diff_text = "\n".join(diff) + "\n"
    if args.output:
        Path(args.output).write_text(diff_text)
        log.info("Diff written to %s", args.output)
    else:
        print(diff_text)

    sys.exit(1)


if __name__ == "__main__":
    main()
```