The script is ready — here's the content (output only, no fences, as requested):

```
"""
config_compliance.py - Network device configuration compliance auditor.
...
```

Since the write was blocked, here is the complete script content to copy:

---

"""
config_compliance.py - Network device configuration compliance auditor.

Fetches the running configuration from a device via SSH and compares it against
a local golden/baseline config file. Reports lines that are required but missing
from the device and lines present on the device but absent from the baseline.

Usage:
    python config_compliance.py -H 192.168.1.1 -u admin -p secret \
        --baseline golden.cfg

    python config_compliance.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa \
        --baseline baseline.cfg --output report.txt --missing-only

Prerequisites:
    pip install paramiko

Exit codes:
    0 = fully compliant (running config matches baseline)
    1 = non-compliant or error
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def connect(host, port, username, password=None, key_path=None, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Either --password or --key must be provided")
    client.connect(**kwargs)
    return client


def fetch_running_config(client, command="show running-config", wait=3.0):
    channel = client.invoke_shell(width=200, height=5000)
    time.sleep(1.0)
    channel.recv(65535)  # drain banner/prompt

    channel.send(command + "\n")
    time.sleep(wait)

    output = b""
    while channel.recv_ready():
        chunk = channel.recv(65535)
        output += chunk
        time.sleep(0.1)

    channel.close()
    return output.decode("utf-8", errors="replace")


_NOISE_PREFIXES = (
    "!",
    "Building configuration",
    "Current configuration",
    "Last configuration change",
    "NVRAM config",
    "boot-start-marker",
    "boot-end-marker",
)


def strip_noise(lines):
    clean = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if any(s.startswith(p) for p in _NOISE_PREFIXES):
            continue
        if s.startswith("version ") and len(s.split()) == 2:
            continue
        clean.append(s)
    return clean


def load_baseline(path):
    text = Path(path).read_text(encoding="utf-8")
    return strip_noise(text.splitlines())


def compliance_check(running_lines, baseline_lines):
    running_set = set(running_lines)
    baseline_set = set(baseline_lines)
    missing = sorted(baseline_set - running_set)
    unexpected = sorted(running_set - baseline_set)
    return missing, unexpected


def format_report(host, missing, unexpected, n_running, n_baseline):
    out = [
        f"Compliance Report: {host}",
        "=" * 60,
        f"Baseline lines:      {n_baseline}",
        f"Running config lines: {n_running}",
        f"Missing (required, absent from device): {len(missing)}",
        f"Unexpected (on device, not in baseline): {len(unexpected)}",
        "",
    ]
    if missing:
        out.append("--- MISSING REQUIRED LINES ---")
        for line in missing:
            out.append(f"  - {line}")
        out.append("")
    if unexpected:
        out.append("--- UNEXPECTED LINES ---")
        for line in unexpected:
            out.append(f"  + {line}")
        out.append("")
    if not missing and not unexpected:
        out.append("RESULT: COMPLIANT — running config matches baseline exactly.")
    else:
        out.append("RESULT: NON-COMPLIANT")
    return "\n".join(out)


def parse_args():
    p = argparse.ArgumentParser(
        description="Audit device running config compliance against a golden baseline."
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password")
    p.add_argument("-k", "--key", help="Path to SSH private key file")
    p.add_argument("-b", "--baseline", required=True, help="Path to baseline config file")
    p.add_argument(
        "-c", "--command",
        default="show running-config",
        help="Command to retrieve running config (default: 'show running-config')",
    )
    p.add_argument("-o", "--output", help="Write report to file instead of stdout")
    p.add_argument(
        "--wait", type=float, default=3.0,
        help="Seconds to wait for device output (default: 3.0)",
    )
    p.add_argument(
        "--missing-only", action="store_true",
        help="Report only missing lines; suppress unexpected-line findings",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key:
        logger.error("Provide --password or --key for authentication")
        sys.exit(1)

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        logger.error("Baseline file not found: %s", args.baseline)
        sys.exit(1)

    logger.info("Loading baseline from %s", args.baseline)
    baseline_lines = load_baseline(baseline_path)
    logger.info("Baseline: %d significant lines", len(baseline_lines))

    logger.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        client = connect(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            key_path=args.key,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        logger.info("Running: %s", args.command)
        raw = fetch_running_config(client, command=args.command, wait=args.wait)
    finally:
        client.close()

    running_lines = strip_noise(raw.splitlines())
    logger.info("Running config: %d significant lines", len(running_lines))

    missing, unexpected = compliance_check(running_lines, baseline_lines)
    if args.missing_only:
        unexpected = []

    report = format_report(
        args.host, missing, unexpected, len(running_lines), len(baseline_lines)
    )

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        logger.info("Report written to %s", args.output)
    else:
        print(report)

    sys.exit(0 if (not missing and not unexpected) else 1)


if __name__ == "__main__":
    main()