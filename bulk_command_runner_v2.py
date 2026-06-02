Network Device Health Monitor

Polls CPU utilization, memory usage, and uptime from Cisco IOS/NX-OS devices
via SSH and produces a per-device health summary. Useful for pre-maintenance
checks, NOC dashboards, and alerting pipelines.

Usage:
    python health_monitor.py --host 192.168.1.1 --username admin --password secret
    python health_monitor.py --hosts hosts.txt --username admin --key-file ~/.ssh/id_rsa
    python health_monitor.py --host 192.168.1.1 --username admin --password secret --json

Prerequisites:
    pip install paramiko
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from typing import Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class DeviceHealth:
    host: str
    reachable: bool
    uptime: Optional[str] = None
    cpu_5min: Optional[float] = None
    mem_used_pct: Optional[float] = None
    error: Optional[str] = None


def _exec(client: paramiko.SSHClient, command: str, timeout: int = 10) -> str:
    _, stdout, _ = client.exec_command(command, timeout=timeout)
    return stdout.read().decode(errors="replace")


def connect(
    host: str,
    username: str,
    password: str,
    key_file: str,
    port: int,
    timeout: int,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(hostname=host, port=port, username=username, timeout=timeout)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def parse_cpu(output: str) -> Optional[float]:
    # IOS: "five minutes: 7%"
    m = re.search(r"five minutes:\s*(\d+)%", output)
    if m:
        return float(m.group(1))
    # NX-OS: three-column float percentages, last column is 5-min
    m = re.search(r"\d+\.\d+%\s+\d+\.\d+%\s+(\d+\.\d+)%", output)
    if m:
        return float(m.group(1))
    return None


def parse_memory(output: str) -> Optional[float]:
    # IOS: "Processor Pool Total: 123456 Used: 78901 Free: 44555"
    m = re.search(r"Total:\s*(\d+)\s+Used:\s*(\d+)", output)
    if m:
        total, used = int(m.group(1)), int(m.group(2))
        return round(used / total * 100, 1) if total else None
    return None


def parse_uptime(output: str) -> Optional[str]:
    m = re.search(r"uptime is (.+)", output, re.IGNORECASE)
    return m.group(1).strip() if m else None


def poll_device(
    host: str,
    username: str,
    password: str,
    key_file: str,
    port: int,
    timeout: int,
) -> DeviceHealth:
    health = DeviceHealth(host=host, reachable=False)
    try:
        client = connect(host, username, password, key_file, port, timeout)
        health.reachable = True
        try:
            health.uptime = parse_uptime(_exec(client, "show version"))
            health.cpu_5min = parse_cpu(_exec(client, "show processes cpu"))
            health.mem_used_pct = parse_memory(_exec(client, "show processes memory"))
        finally:
            client.close()
    except paramiko.AuthenticationException:
        health.error = "authentication failed"
        log.error("%s: authentication failed", host)
    except Exception as exc:
        health.error = str(exc)
        log.error("%s: %s", host, exc)
    return health


def print_table(results: list) -> None:
    print(f"\n{'HOST':<22} {'UP':<5} {'CPU 5m%':<10} {'MEM%':<8} UPTIME / ERROR")
    print("-" * 80)
    for r in results:
        cpu = f"{r.cpu_5min:.1f}" if r.cpu_5min is not None else "n/a"
        mem = f"{r.mem_used_pct:.1f}" if r.mem_used_pct is not None else "n/a"
        detail = r.uptime or r.error or "n/a"
        status = "YES" if r.reachable else "NO"
        print(f"{r.host:<22} {status:<5} {cpu:<10} {mem:<8} {detail}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="SSH-based network device health monitor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single device IP or hostname")
    group.add_argument("--hosts", metavar="FILE", help="File with one host per line")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", default="")
    parser.add_argument("--key-file", default="", metavar="PATH")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=10, metavar="SECS")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON")
    args = parser.parse_args()

    if args.hosts:
        try:
            with open(args.hosts) as fh:
                hosts = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except OSError as exc:
            log.error("Cannot read hosts file: %s", exc)
            return 1
    else:
        hosts = [args.host]

    results = []
    for host in hosts:
        log.info("Polling %s", host)
        results.append(
            poll_device(host, args.username, args.password, args.key_file, args.port, args.timeout)
        )

    if args.as_json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        print_table(results)

    return 1 if any(not r.reachable for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())