Writing the interface error rate monitor script now — distinct from existing status scripts by focusing on counter thresholds and monitoring-system-compatible output.

```python
#!/usr/bin/env python3
"""
Interface Error Rate Monitor — paramiko-network-scripts

Purpose:
    Connect to a network device via SSH and inspect interface error counters
    (CRC errors, input errors, output drops, runts, giants). Report interfaces
    that exceed configurable thresholds and emit a Nagios-compatible exit code
    so the script can be wired directly into Nagios/Icinga/Zabbix.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 10.0.0.1 -u admin -k ~/.ssh/id_rsa \
        --crc-threshold 50 --drop-threshold 1000 --output json

Prerequisites:
    pip install paramiko
    Device must accept SSH and respond to "show interfaces" (Cisco IOS syntax).
    For other platforms adjust SHOW_CMD and the parse_interface_block() regex.

Exit codes (Nagios-compatible):
    0  OK      — all interfaces within thresholds
    1  WARNING — at least one counter near threshold (>50 % of limit)
    2  CRITICAL — at least one counter exceeds threshold
    3  UNKNOWN  — connection or parse failure
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

import paramiko

SHOW_CMD = "show interfaces"
TIMEOUT = 30
RECV_BYTES = 65535

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.WARNING,
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    crc: int = 0
    input_errors: int = 0
    output_drops: int = 0
    runts: int = 0
    giants: int = 0
    flags: list = field(default_factory=list)


def ssh_connect(host: str, port: int, username: str,
                password: Optional[str], key_path: Optional[str]) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(hostname=host, port=port, username=username,
                          timeout=TIMEOUT, look_for_keys=False, allow_agent=False)
    if key_path:
        connect_kwargs["key_filename"] = key_path
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key-file")
    client.connect(**connect_kwargs)
    return client


def run_command(client: paramiko.SSHClient, cmd: str) -> str:
    _, stdout, stderr = client.exec_command(cmd, timeout=TIMEOUT)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.warning("stderr: %s", err)
    return output


def parse_interfaces(raw: str) -> list[InterfaceErrors]:
    blocks = re.split(r"\n(?=\S)", raw)
    results = []
    for block in blocks:
        name_match = re.match(r"^(\S+)\s+is\s+\S+", block)
        if not name_match:
            continue
        iface = InterfaceErrors(name=name_match.group(1))

        def extract(pattern, default=0):
            m = re.search(pattern, block)
            return int(m.group(1).replace(",", "")) if m else default

        iface.input_errors = extract(r"(\d[\d,]*)\s+input errors")
        iface.crc = extract(r"(\d[\d,]*)\s+CRC")
        iface.runts = extract(r"(\d[\d,]*)\s+runts")
        iface.giants = extract(r"(\d[\d,]*)\s+giants")
        iface.output_drops = extract(r"(\d[\d,]*)\s+output drops")
        results.append(iface)
    return results


def evaluate(interfaces: list[InterfaceErrors],
             crc_limit: int, drop_limit: int) -> tuple[int, list[dict]]:
    problems = []
    worst = 0
    for iface in interfaces:
        iface_problems = []
        for label, value, limit in [
            ("crc", iface.crc, crc_limit),
            ("input_errors", iface.input_errors, crc_limit),
            ("output_drops", iface.output_drops, drop_limit),
        ]:
            if value > limit:
                iface_problems.append({"counter": label, "value": value, "threshold": limit, "severity": "CRITICAL"})
                worst = max(worst, 2)
            elif value > limit // 2:
                iface_problems.append({"counter": label, "value": value, "threshold": limit, "severity": "WARNING"})
                worst = max(worst, 1)
        if iface_problems:
            problems.append({"interface": iface.name, "issues": iface_problems})
    return worst, problems


def main():
    parser = argparse.ArgumentParser(description="Interface error counter health check")
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("-k", "--key-file", dest="key_file", default=None,
                        help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--crc-threshold", type=int, default=100, metavar="N",
                        help="Max CRC/input errors before CRITICAL (default: 100)")
    parser.add_argument("--drop-threshold", type=int, default=500, metavar="N",
                        help="Max output drops before CRITICAL (default: 500)")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        client = ssh_connect(args.host, args.port, args.username,
                             args.password, args.key_file)
        raw = run_command(client, SHOW_CMD)
        client.close()
    except (paramiko.AuthenticationException, paramiko.SSHException) as exc:
        print(f"UNKNOWN: SSH error — {exc}")
        sys.exit(3)
    except Exception as exc:
        print(f"UNKNOWN: {exc}")
        sys.exit(3)

    interfaces = parse_interfaces(raw)
    if not interfaces:
        print("UNKNOWN: no interfaces parsed — check device output format")
        sys.exit(3)

    exit_code, problems = evaluate(interfaces, args.crc_threshold, args.drop_threshold)

    status_label = {0: "OK", 1: "WARNING", 2: "CRITICAL"}.get(exit_code, "UNKNOWN")

    if args.output == "json":
        print(json.dumps({
            "status": status_label,
            "exit_code": exit_code,
            "interfaces_checked": len(interfaces),
            "problems": problems,
        }, indent=2))
    else:
        if not problems:
            print(f"{status_label}: {len(interfaces)} interfaces checked, all counters within thresholds")
        else:
            summary = "; ".join(
                f"{p['interface']}({', '.join(i['counter'] + '=' + str(i['value']) for i in p['issues'])})"
                for p in problems
            )
            print(f"{status_label}: {summary}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
```