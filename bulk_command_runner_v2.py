Writing a port security audit script — distinct from all existing scripts, focused on Cisco IOS switch security posture.

```python
"""
port_security.py - Cisco IOS Port Security Auditor

Connects to a Cisco IOS switch via SSH and audits port security configuration
across all secured interfaces. Reports max MAC limits, current MAC counts,
violation modes, and highlights any interfaces actively in violation state.

Usage:
    python port_security.py -H 192.168.1.1 -u admin -p secret
    python port_security.py -H 192.168.1.1 -u admin -p secret --violations-only
    python port_security.py -H 192.168.1.1 -u admin -p secret --csv report.csv

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target switch.
    Port security must be configured on at least one interface.
"""

import argparse
import csv
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

BUFFER_SIZE = 65535
RECV_TIMEOUT = 5.0


def ssh_connect(host, username, password, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def send_command(shell, command, timeout=RECV_TIMEOUT):
    shell.send(command + "\n")
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(BUFFER_SIZE).decode("utf-8", errors="replace")
            output += chunk
            if re.search(r"[#>]\s*$", chunk):
                break
        time.sleep(0.1)
    return output


def parse_port_security(raw):
    """
    Parse `show port-security` tabular output.

    Expected columns: Secure Port | MaxSecureAddr | CurrentAddr |
                      SecurityViolation | Security Action
    """
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        m = re.match(
            r"^((?:Fa|Gi|Te|Et|Eth)\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)",
            line,
            re.IGNORECASE,
        )
        if m:
            entries.append({
                "interface": m.group(1),
                "max_addr": int(m.group(2)),
                "current_addr": int(m.group(3)),
                "violations": int(m.group(4)),
                "action": m.group(5),
            })
    return entries


def print_table(entries, violations_only):
    col_iface = 22
    header = (
        f"{'Interface':<{col_iface}} {'MaxMAC':>6} {'CurMAC':>6} "
        f"{'Violations':>10} {'Action':<12} Status"
    )
    bar = "-" * len(header)
    print(bar)
    print(header)
    print(bar)

    shown = 0
    for e in entries:
        in_violation = e["violations"] > 0
        if violations_only and not in_violation:
            continue
        status = "!! VIOLATION !!" if in_violation else "OK"
        print(
            f"{e['interface']:<{col_iface}} {e['max_addr']:>6} {e['current_addr']:>6} "
            f"{e['violations']:>10} {e['action']:<12} {status}"
        )
        shown += 1

    print(bar)
    total_violated = sum(1 for e in entries if e["violations"] > 0)
    if violations_only:
        print(f"Interfaces in violation: {shown}")
    else:
        print(
            f"Secured interfaces: {len(entries)}  |  "
            f"In violation: {total_violated}"
        )


def write_csv(entries, filepath):
    fields = ["interface", "max_addr", "current_addr", "violations", "action"]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(entries)
    log.info("Results written to %s", filepath)


def main():
    parser = argparse.ArgumentParser(
        description="Audit port security configuration on a Cisco IOS switch."
    )
    parser.add_argument("-H", "--host", required=True, help="Switch hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=10, help="Connection timeout in seconds"
    )
    parser.add_argument("--csv", metavar="FILE", help="Save results to a CSV file")
    parser.add_argument(
        "--violations-only",
        action="store_true",
        help="Show only interfaces with active security violations",
    )
    args = parser.parse_args()

    log.info("Connecting to %s", args.host)
    try:
        client = ssh_connect(
            args.host, args.username, args.password, args.port, args.timeout
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection to %s failed: %s", args.host, exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell()
        time.sleep(0.5)
        shell.recv(BUFFER_SIZE)
        send_command(shell, "terminal length 0")
        log.info("Fetching port security table")
        raw = send_command(shell, "show port-security", timeout=RECV_TIMEOUT)
    finally:
        client.close()

    entries = parse_port_security(raw)

    if not entries:
        log.warning(
            "No secured interfaces found — port security may not be configured"
        )
        sys.exit(0)

    print(f"\nPort Security Audit — {args.host}\n")
    print_table(entries, args.violations_only)

    if args.csv:
        write_csv(entries, args.csv)


if __name__ == "__main__":
    main()
```