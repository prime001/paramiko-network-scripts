```python
"""
device_health_monitor.py — SSH-based device health checker using Paramiko.

Purpose:
    Polls CPU utilization, memory usage, and uptime from one or more network
    devices over SSH and flags any resources that exceed configurable thresholds.
    Useful for quick NOC spot-checks or pre/post-change health validation.

Usage:
    python device_health_monitor.py -H 192.168.1.1 -u admin -p secret
    python device_health_monitor.py --hosts-file devices.txt -u admin \
        --cpu-threshold 70 --mem-threshold 80 --output report.txt

Prerequisites:
    pip install paramiko
    Target devices must allow SSH and support IOS/IOS-XE show commands.
    devices.txt format: one IP or hostname per line (# lines are comments).
"""

import argparse
import getpass
import logging
import re
import sys
from datetime import datetime

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

COMMANDS = {
    "cpu": "show processes cpu | include CPU utilization",
    "memory": "show processes memory | include Processor",
    "uptime": "show version | include uptime",
}


def parse_cpu(output: str) -> float | None:
    match = re.search(r"five minutes:\s+(\d+)%", output)
    if match:
        return float(match.group(1))
    match = re.search(r"CPU utilization.*?(\d+)%/", output)
    if match:
        return float(match.group(1))
    return None


def parse_memory(output: str) -> tuple[int, int] | tuple[None, None]:
    match = re.search(r"Processor\s+\d+\s+(\d+)\s+(\d+)", output)
    if match:
        used = int(match.group(1))
        free = int(match.group(2))
        return used, free
    return None, None


def run_command(channel: paramiko.Channel, command: str, timeout: int = 15) -> str:
    channel.send(command + "\n")
    output = ""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(4096).decode("utf-8", errors="replace")
            output += chunk
            if re.search(r"[>#]", chunk.split("\n")[-1]):
                break
        time.sleep(0.1)
    return output


def check_device(host: str, username: str, password: str,
                 port: int, timeout: int) -> dict:
    result = {"host": host, "status": "unreachable", "cpu": None,
              "mem_used": None, "mem_free": None, "mem_pct": None,
              "uptime": None, "error": None}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, look_for_keys=False,
                       allow_agent=False)
        shell = client.invoke_shell(width=200, height=50)
        import time
        time.sleep(1)
        if shell.recv_ready():
            shell.recv(4096)
        shell.send("terminal length 0\n")
        time.sleep(0.5)
        if shell.recv_ready():
            shell.recv(4096)

        cpu_out = run_command(shell, COMMANDS["cpu"])
        mem_out = run_command(shell, COMMANDS["memory"])
        up_out = run_command(shell, COMMANDS["uptime"])

        result["cpu"] = parse_cpu(cpu_out)
        used, free = parse_memory(mem_out)
        result["mem_used"] = used
        result["mem_free"] = free
        if used is not None and free is not None and (used + free) > 0:
            result["mem_pct"] = round(used / (used + free) * 100, 1)

        up_match = re.search(r"uptime is (.+)", up_out)
        result["uptime"] = up_match.group(1).strip() if up_match else "unknown"
        result["status"] = "ok"
        shell.close()
    except paramiko.AuthenticationException:
        result["error"] = "authentication failed"
        log.warning("%s: authentication failed", host)
    except Exception as exc:
        result["error"] = str(exc)
        log.warning("%s: %s", host, exc)
    finally:
        client.close()
    return result


def format_report(results: list[dict], cpu_thresh: int, mem_thresh: int) -> str:
    lines = [
        f"Device Health Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Thresholds: CPU >{cpu_thresh}%  Memory >{mem_thresh}%",
        "=" * 72,
    ]
    for r in results:
        lines.append(f"\nHost: {r['host']}")
        if r["status"] != "ok":
            lines.append(f"  STATUS : UNREACHABLE ({r['error']})")
            continue
        cpu_flag = " [ALERT]" if r["cpu"] and r["cpu"] > cpu_thresh else ""
        mem_flag = " [ALERT]" if r["mem_pct"] and r["mem_pct"] > mem_thresh else ""
        lines.append(f"  Uptime : {r['uptime']}")
        lines.append(f"  CPU    : {r['cpu']}% (5-min avg){cpu_flag}")
        lines.append(f"  Memory : {r['mem_pct']}% used "
                     f"({r['mem_used']} / {r['mem_free']} bytes free){mem_flag}")
    lines.append("\n" + "=" * 72)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSH device health monitor — CPU, memory, uptime")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--host", help="Single device IP or hostname")
    group.add_argument("--hosts-file", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", help="Omit to prompt securely")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=15, metavar="SEC")
    parser.add_argument("--cpu-threshold", type=int, default=80, metavar="PCT")
    parser.add_argument("--mem-threshold", type=int, default=85, metavar="PCT")
    parser.add_argument("--output", help="Write report to file instead of stdout")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")

    if args.host:
        hosts = [args.host]
    else:
        try:
            with open(args.hosts_file) as fh:
                hosts = [l.strip() for l in fh
                         if l.strip() and not l.startswith("#")]
        except OSError as exc:
            log.error("Cannot read hosts file: %s", exc)
            sys.exit(1)

    if not hosts:
        log.error("No hosts to check.")
        sys.exit(1)

    results = []
    for host in hosts:
        log.info("Checking %s …", host)
        results.append(check_device(host, args.username, password,
                                    args.port, args.timeout))

    report = format_report(results, args.cpu_threshold, args.mem_threshold)
    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(report + "\n")
            log.info("Report written to %s", args.output)
        except OSError as exc:
            log.error("Cannot write output file: %s", exc)
            sys.exit(1)
    else:
        print(report)

    alerts = sum(
        1 for r in results
        if r["status"] == "ok" and (
            (r["cpu"] and r["cpu"] > args.cpu_threshold) or
            (r["mem_pct"] and r["mem_pct"] > args.mem_threshold)
        )
    )
    if alerts:
        log.warning("%d device(s) exceeded thresholds.", alerts)
        sys.exit(2)


if __name__ == "__main__":
    main()
```