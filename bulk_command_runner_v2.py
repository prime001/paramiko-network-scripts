device_health_check.py - Network device health snapshot collector

Connects to one or more Cisco IOS/IOS-XE devices and collects CPU utilization,
memory usage, uptime, and interface error counters. Results are printed as a
formatted table and optionally written to JSON.

Usage:
    python device_health_check.py -H 192.168.1.1 -u admin -p secret
    python device_health_check.py --host-file hosts.txt -u admin --ask-pass
    python device_health_check.py -H 10.0.0.1 -u admin -p secret --json out.json

Prerequisites:
    pip install paramiko
    SSH access enabled on target devices (ip ssh version 2)
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_exec(client, command, timeout=10):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    if err.strip():
        log.debug("stderr from '%s': %s", command, err.strip())
    return out


def connect(host, username, password, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def parse_cpu(output):
    """Extract 5-second CPU % from 'show processes cpu'."""
    match = re.search(r"CPU utilization.*?(\d+)%/", output)
    return int(match.group(1)) if match else None


def parse_memory(output):
    """Return (used_kb, free_kb) from 'show memory statistics'."""
    match = re.search(r"Processor\s+\S+\s+(\d+)\s+(\d+)", output)
    if match:
        used = int(match.group(1)) // 1024
        free = int(match.group(2)) // 1024
        return used, free
    return None, None


def parse_uptime(output):
    """Extract uptime string from 'show version'."""
    match = re.search(r"uptime is (.+)", output)
    return match.group(1).strip() if match else "unknown"


def parse_interface_errors(output):
    """Count interfaces with non-zero input errors."""
    error_ifaces = []
    current = None
    for line in output.splitlines():
        iface_match = re.match(r"^(\S+) is ", line)
        if iface_match:
            current = iface_match.group(1)
        if current and re.search(r"\b[1-9]\d* input errors", line):
            error_ifaces.append(current)
    return error_ifaces


def collect_health(host, username, password, port=22):
    result = {"host": host, "error": None}
    try:
        client = connect(host, username, password, port=port)
        result["cpu_5s_pct"] = parse_cpu(ssh_exec(client, "show processes cpu"))
        used, free = parse_memory(ssh_exec(client, "show memory statistics"))
        result["mem_used_kb"] = used
        result["mem_free_kb"] = free
        result["uptime"] = parse_uptime(ssh_exec(client, "show version"))
        result["error_interfaces"] = parse_interface_errors(
            ssh_exec(client, "show interfaces")
        )
        client.close()
    except paramiko.AuthenticationException:
        result["error"] = "authentication failed"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def print_table(results):
    header = f"{'Host':<20} {'CPU%':>5} {'Mem Used(KB)':>13} {'Mem Free(KB)':>13} {'Err Ifaces':>10}  Uptime"
    print(header)
    print("-" * len(header))
    for r in results:
        if r["error"]:
            print(f"{r['host']:<20}  ERROR: {r['error']}")
            continue
        cpu = f"{r['cpu_5s_pct']:>4}%" if r["cpu_5s_pct"] is not None else "   n/a"
        mem_used = f"{r['mem_used_kb']:>13,}" if r["mem_used_kb"] is not None else "          n/a"
        mem_free = f"{r['mem_free_kb']:>13,}" if r["mem_free_kb"] is not None else "          n/a"
        err_count = len(r.get("error_interfaces", []))
        uptime = r.get("uptime", "unknown")
        print(f"{r['host']:<20} {cpu} {mem_used} {mem_free} {err_count:>10}  {uptime}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect CPU, memory, and error stats from Cisco IOS devices."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--host", help="Single device IP or hostname")
    group.add_argument("--host-file", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (omit to prompt)")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--json", metavar="FILE", help="Write results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.ask_pass or not args.password:
        password = getpass.getpass("SSH password: ")
    else:
        password = args.password

    if args.host:
        hosts = [args.host]
    else:
        try:
            with open(args.host_file) as f:
                hosts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except OSError as e:
            sys.exit(f"Cannot read host file: {e}")

    results = []
    for host in hosts:
        log.debug("Connecting to %s", host)
        results.append(collect_health(host, args.username, password, port=args.port))

    print_table(results)

    if args.json:
        try:
            with open(args.json, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\nResults written to {args.json}")
        except OSError as e:
            sys.exit(f"Cannot write JSON: {e}")