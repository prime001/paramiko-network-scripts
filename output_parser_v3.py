```python
"""
device_health.py - Network Device Health Monitor

Connects to a Cisco network device via SSH and collects CPU utilization,
memory usage, and system uptime. Supports Cisco IOS and NX-OS platforms.
Outputs a human-readable table or JSON for downstream processing.

Usage:
    python device_health.py -d 192.168.1.1 -u admin -p secret
    python device_health.py -d 192.168.1.1 -u admin --ask-pass --json
    python device_health.py -d 192.168.1.1 -u admin -p secret --platform nxos

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    IOS:   ip ssh version 2
    NX-OS: feature ssh
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
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_exec(client, command, timeout=10):
    _, stdout, _ = client.exec_command(command, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


def parse_ios_cpu(output):
    match = re.search(
        r"CPU utilization for five seconds: (\d+)%/\d+%; "
        r"one minute: (\d+)%; five minutes: (\d+)%",
        output,
    )
    if not match:
        return {}
    return {
        "cpu_5sec_pct": int(match.group(1)),
        "cpu_1min_pct": int(match.group(2)),
        "cpu_5min_pct": int(match.group(3)),
    }


def parse_ios_memory(output):
    match = re.search(r"Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)", output)
    if not match:
        return {}
    total, used, free = int(match.group(1)), int(match.group(2)), int(match.group(3))
    return {
        "mem_total_kb": total // 1024,
        "mem_used_kb": used // 1024,
        "mem_free_kb": free // 1024,
        "mem_used_pct": round(used / total * 100, 1) if total else 0,
    }


def parse_ios_version(output):
    result = {}
    uptime = re.search(r"uptime is (.+)", output)
    hostname = re.search(r"^(\S+)\s+uptime", output, re.MULTILINE)
    if uptime:
        result["uptime"] = uptime.group(1).strip()
    if hostname:
        result["hostname"] = hostname.group(1)
    return result


def parse_nxos_resources(output):
    result = {}
    cpu = re.search(r"CPU states\s*:\s*([\d.]+)% user,\s*([\d.]+)% kernel", output)
    mem = re.search(r"Memory usage:\s+(\d+)K total,\s+(\d+)K used,\s+(\d+)K free", output)
    if cpu:
        user, kernel = float(cpu.group(1)), float(cpu.group(2))
        result.update({
            "cpu_user_pct": user,
            "cpu_kernel_pct": kernel,
            "cpu_total_pct": round(user + kernel, 1),
        })
    if mem:
        total, used, free = int(mem.group(1)), int(mem.group(2)), int(mem.group(3))
        result.update({
            "mem_total_kb": total,
            "mem_used_kb": used,
            "mem_free_kb": free,
            "mem_used_pct": round(used / total * 100, 1) if total else 0,
        })
    return result


def collect_ios(client):
    metrics = {}
    metrics.update(parse_ios_cpu(
        ssh_exec(client, "show processes cpu | include CPU utilization")
    ))
    metrics.update(parse_ios_memory(
        ssh_exec(client, "show processes memory | include Processor")
    ))
    metrics.update(parse_ios_version(
        ssh_exec(client, "show version | include uptime")
    ))
    return metrics


def collect_nxos(client):
    metrics = parse_nxos_resources(ssh_exec(client, "show system resources"))
    ver_out = ssh_exec(client, "show version | include uptime")
    match = re.search(r"Kernel uptime is (.+)", ver_out)
    if match:
        metrics["uptime"] = match.group(1).strip()
    hostname = re.search(r"(\S+)\s+uptime", ver_out, re.MULTILINE)
    if hostname:
        metrics["hostname"] = hostname.group(1)
    return metrics


def connect(host, port, username, password, timeout):
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


def print_table(host, metrics):
    width = 50
    print(f"\n{'=' * width}")
    print(f"  Device Health: {host}")
    if "hostname" in metrics:
        print(f"  Hostname     : {metrics['hostname']}")
    if "uptime" in metrics:
        print(f"  Uptime       : {metrics['uptime']}")
    print(f"{'=' * width}")
    skip = {"hostname", "uptime", "device", "platform", "collected_at"}
    for key, val in metrics.items():
        if key in skip:
            continue
        label = key.replace("_", " ").title()
        suffix = "%" if "pct" in key else " KB" if "kb" in key else ""
        print(f"  {label:<24}: {val}{suffix}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Collect CPU, memory, and uptime health metrics from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--platform",
        choices=["ios", "nxos"],
        default="ios",
        help="Device OS platform (default: ios)",
    )
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout in seconds")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or not password:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        log.debug("Connecting to %s:%d", args.device, args.port)
        client = connect(args.device, args.port, args.username, password, args.timeout)
    except paramiko.AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Cannot connect to {args.device}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        metrics = collect_ios(client) if args.platform == "ios" else collect_nxos(client)
    except Exception as exc:
        print(f"ERROR: Failed to collect metrics: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

    if not metrics:
        print("WARNING: No metrics parsed; check platform selection.", file=sys.stderr)
        sys.exit(2)

    metrics["device"] = args.device
    metrics["platform"] = args.platform
    metrics["collected_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if args.as_json:
        print(json.dumps(metrics, indent=2))
    else:
        print_table(args.device, metrics)


if __name__ == "__main__":
    main()
```