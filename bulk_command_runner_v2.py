cpu_memory_monitor.py - Network Device CPU and Memory Monitor

Purpose:
    Poll CPU utilization and memory statistics from one or more Cisco IOS/IOS-XE
    devices via SSH and print a formatted health summary table.  Useful for
    capacity planning, pre/post-change baselining, or quick ops checks.

Usage:
    Single device:
        python cpu_memory_monitor.py -d 192.168.1.1 -u admin -p secret

    Device list file (one IP/hostname per line, # for comments):
        python cpu_memory_monitor.py -f devices.txt -u admin -p secret

    Save results to CSV:
        python cpu_memory_monitor.py -f devices.txt -u admin -p secret --csv out.csv

Prerequisites:
    pip install paramiko
    SSH must be enabled on target devices (transport ssh version 2).
    Account needs privilege level 1 (show commands only).
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import csv
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.WARNING,
)
log = logging.getLogger(__name__)

CONNECT_TIMEOUT = 15
RECV_TIMEOUT = 30
MAX_WORKERS = 10


@dataclass
class DeviceResult:
    host: str
    cpu_5sec: Optional[str] = None
    cpu_1min: Optional[str] = None
    cpu_5min: Optional[str] = None
    mem_total_kb: Optional[int] = None
    mem_used_kb: Optional[int] = None
    mem_free_kb: Optional[int] = None
    error: Optional[str] = None


def _exec(client: paramiko.SSHClient, command: str) -> str:
    _, stdout, _ = client.exec_command(command, timeout=RECV_TIMEOUT)
    return stdout.read().decode(errors="replace")


def _parse_cpu(output: str):
    m = re.search(
        r"CPU utilization for five seconds:\s*(\d+)%.*?"
        r"one minute:\s*(\d+)%.*?"
        r"five minutes:\s*(\d+)%",
        output,
        re.IGNORECASE | re.DOTALL,
    )
    if m:
        return m.group(1), m.group(2), m.group(3)
    return None, None, None


def _parse_memory(output: str):
    # IOS: "Processor  <addr>  <total>  <used>  <free>  ..."  (values in bytes)
    m = re.search(r"Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)", output)
    if m:
        total = int(m.group(1)) // 1024
        used = int(m.group(2)) // 1024
        free = int(m.group(3)) // 1024
        return total, used, free
    return None, None, None


def poll_device(host: str, username: str, password: str, port: int) -> DeviceResult:
    result = DeviceResult(host=host)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        cpu_out = _exec(client, "show processes cpu")
        mem_out = _exec(client, "show processes memory")
        result.cpu_5sec, result.cpu_1min, result.cpu_5min = _parse_cpu(cpu_out)
        result.mem_total_kb, result.mem_used_kb, result.mem_free_kb = _parse_memory(mem_out)
    except paramiko.AuthenticationException:
        result.error = "auth failed"
        log.error("%s: authentication failed", host)
    except paramiko.SSHException as exc:
        result.error = f"SSH error: {exc}"
        log.error("%s: %s", host, exc)
    except OSError as exc:
        result.error = f"connect error: {exc}"
        log.error("%s: %s", host, exc)
    finally:
        client.close()
    return result


def _mem_pct(used, total) -> str:
    if used is not None and total and total > 0:
        return f"{used / total * 100:.1f}%"
    return "n/a"


def print_table(results: List[DeviceResult]) -> None:
    col = {
        "host": 22, "5s": 7, "1m": 7, "5m": 7,
        "mem_total": 11, "mem_used": 11, "mem_pct": 9,
    }
    hdr = (
        f"{'Host':<{col['host']}} {'CPU 5s':>{col['5s']}} {'CPU 1m':>{col['1m']}}"
        f" {'CPU 5m':>{col['5m']}} {'MemTotal(K)':>{col['mem_total']}}"
        f" {'MemUsed(K)':>{col['mem_used']}} {'Mem%':>{col['mem_pct']}}  Status"
    )
    print(hdr)
    print("-" * len(hdr))
    for r in sorted(results, key=lambda x: x.host):
        if r.error:
            print(f"{r.host:<{col['host']}} {'':>{col['5s']}} {'':>{col['1m']}}"
                  f" {'':>{col['5m']}} {'':>{col['mem_total']}} {'':>{col['mem_used']}}"
                  f" {'':>{col['mem_pct']}}  ERROR: {r.error}")
        else:
            cpu5s = f"{r.cpu_5sec}%" if r.cpu_5sec else "n/a"
            cpu1m = f"{r.cpu_1min}%" if r.cpu_1min else "n/a"
            cpu5m = f"{r.cpu_5min}%" if r.cpu_5min else "n/a"
            mt = str(r.mem_total_kb) if r.mem_total_kb is not None else "n/a"
            mu = str(r.mem_used_kb) if r.mem_used_kb is not None else "n/a"
            mp = _mem_pct(r.mem_used_kb, r.mem_total_kb)
            print(
                f"{r.host:<{col['host']}} {cpu5s:>{col['5s']}} {cpu1m:>{col['1m']}}"
                f" {cpu5m:>{col['5m']}} {mt:>{col['mem_total']}} {mu:>{col['mem_used']}}"
                f" {mp:>{col['mem_pct']}}  OK"
            )


def write_csv(results: List[DeviceResult], path: str) -> None:
    fields = [
        "host", "cpu_5sec", "cpu_1min", "cpu_5min",
        "mem_total_kb", "mem_used_kb", "mem_free_kb", "error",
    ]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({f: getattr(r, f) for f in fields})
    print(f"Results saved to {path}")


def load_hosts(path: str) -> List[str]:
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Poll CPU and memory utilization from Cisco IOS devices over SSH."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-d", "--device", metavar="HOST", help="Single device IP or hostname")
    src.add_argument("-f", "--file", metavar="FILE", help="File of device IPs (one per line)")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--workers", type=int, default=MAX_WORKERS,
                        help="Max parallel SSH connections (default: %(default)s)")
    parser.add_argument("--csv", dest="csv_out", metavar="FILE", help="Write results to CSV")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    hosts = [args.device] if args.device else load_hosts(args.file)
    if not hosts:
        parser.error("No hosts to poll.")

    results: List[DeviceResult] = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(hosts))) as pool:
        futures = {
            pool.submit(poll_device, h, args.username, args.password, args.port): h
            for h in hosts
        }
        for future in as_completed(futures):
            results.append(future.result())

    print_table(results)

    if args.csv_out:
        write_csv(results, args.csv_out)

    if any(r.error for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()