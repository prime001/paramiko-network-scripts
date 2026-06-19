```python
"""
interface_error_monitor.py - Interface error counter monitor via SSH.

Connects to a network device over SSH, collects interface error counters
(CRC errors, input errors, output drops, resets), and flags interfaces
that exceed configurable thresholds. Useful for identifying degraded links
before they trigger outages.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \
        --crc-threshold 10 --drop-threshold 100 --interface GigabitEthernet0/1

Prerequisites:
    pip install paramiko
    Device must accept SSH and support 'show interfaces' (IOS/IOS-XE/NX-OS).
"""

import argparse
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

DEFAULT_PORT = 22
DEFAULT_TIMEOUT = 30
RECV_BUFFER = 65535
COMMAND_DELAY = 1.5


def ssh_connect(host, port, username, password, timeout):
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


def run_command(client, command, delay=COMMAND_DELAY):
    channel = client.invoke_shell()
    time.sleep(0.5)
    channel.recv(RECV_BUFFER)  # flush banner
    channel.send(f"terminal length 0\n")
    time.sleep(0.5)
    channel.recv(RECV_BUFFER)
    channel.send(f"{command}\n")
    time.sleep(delay)
    output = b""
    while channel.recv_ready():
        output += channel.recv(RECV_BUFFER)
        time.sleep(0.1)
    channel.close()
    return output.decode("utf-8", errors="replace")


def parse_interface_errors(output):
    """
    Parse 'show interfaces' output into a dict keyed by interface name.
    Returns counters relevant to link health: input_errors, crc, output_drops,
    interface_resets, last_input, last_output.
    """
    interfaces = {}
    current = None

    for line in output.splitlines():
        # Interface header line
        m = re.match(r"^(\S+\d[\d/.]*).*is (up|down|administratively down)", line)
        if m:
            current = m.group(1)
            interfaces[current] = {
                "status": m.group(2),
                "input_errors": 0,
                "crc": 0,
                "output_drops": 0,
                "interface_resets": 0,
                "last_input": "never",
                "last_output": "never",
            }
            continue

        if current is None:
            continue

        # Input errors line: "X input errors, Y CRC, ..."
        m = re.search(r"(\d+) input errors.*?(\d+) CRC", line)
        if m:
            interfaces[current]["input_errors"] = int(m.group(1))
            interfaces[current]["crc"] = int(m.group(2))

        # Output drops: "X output drops"
        m = re.search(r"(\d+) output drops", line)
        if m:
            interfaces[current]["output_drops"] = int(m.group(1))

        # Interface resets
        m = re.search(r"(\d+) interface resets", line)
        if m:
            interfaces[current]["interface_resets"] = int(m.group(1))

        # Last input/output
        m = re.search(r"Last input (\S+),\s+output (\S+)", line)
        if m:
            interfaces[current]["last_input"] = m.group(1)
            interfaces[current]["last_output"] = m.group(2)

    return interfaces


def check_thresholds(interfaces, crc_threshold, drop_threshold, reset_threshold):
    violations = []
    for name, counters in interfaces.items():
        reasons = []
        if counters["crc"] >= crc_threshold:
            reasons.append(f"CRC={counters['crc']} (threshold {crc_threshold})")
        if counters["output_drops"] >= drop_threshold:
            reasons.append(
                f"output_drops={counters['output_drops']} (threshold {drop_threshold})"
            )
        if counters["interface_resets"] >= reset_threshold:
            reasons.append(
                f"resets={counters['interface_resets']} (threshold {reset_threshold})"
            )
        if reasons:
            violations.append((name, counters["status"], reasons))
    return violations


def report(interfaces, violations, target_interface=None):
    print(f"\n{'Interface':<35} {'Status':<20} {'CRC':>8} {'InErr':>8} {'OutDrop':>8} {'Resets':>7}")
    print("-" * 90)
    for name, c in sorted(interfaces.items()):
        if target_interface and target_interface.lower() not in name.lower():
            continue
        flag = " [!]" if any(name == v[0] for v in violations) else ""
        print(
            f"{name:<35} {c['status']:<20} {c['crc']:>8} {c['input_errors']:>8} "
            f"{c['output_drops']:>8} {c['interface_resets']:>7}{flag}"
        )

    if violations:
        print(f"\nThreshold violations ({len(violations)}):")
        for name, status, reasons in violations:
            print(f"  {name} [{status}]: {', '.join(reasons)}")
    else:
        print("\nNo threshold violations detected.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Monitor interface error counters on a network device."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--interface", help="Filter output to a specific interface")
    parser.add_argument(
        "--crc-threshold", type=int, default=5,
        help="CRC error count to flag as violation (default: 5)",
    )
    parser.add_argument(
        "--drop-threshold", type=int, default=50,
        help="Output drop count to flag as violation (default: 50)",
    )
    parser.add_argument(
        "--reset-threshold", type=int, default=3,
        help="Interface reset count to flag as violation (default: 3)",
    )
    parser.add_argument(
        "--command", default="show interfaces",
        help="Override the show command (default: 'show interfaces')",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = ssh_connect(args.host, args.port, args.username, args.password, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Running: %s", args.command)
        output = run_command(client, args.command)
    except paramiko.SSHException as exc:
        log.error("Command execution failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    interfaces = parse_interface_errors(output)
    if not interfaces:
        log.error("No interface data parsed — check command output or device type")
        sys.exit(1)

    log.info("Parsed %d interfaces", len(interfaces))
    violations = check_thresholds(
        interfaces, args.crc_threshold, args.drop_threshold, args.reset_threshold
    )
    report(interfaces, violations, target_interface=args.interface)

    sys.exit(1 if violations else 0)
```