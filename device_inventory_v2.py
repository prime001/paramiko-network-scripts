```python
"""
device_inventory.py - Network Device Inventory Collector

Connects to one or more network devices via SSH and collects hardware and
software inventory data including platform, version, serial numbers, and
installed modules. Results are written to CSV or JSON for asset tracking.

Usage:
    python device_inventory.py -d 192.168.1.1 -u admin -p secret
    python device_inventory.py -f devices.txt -u admin --ask-pass --output inventory.csv
    python device_inventory.py -d 10.0.0.1,10.0.0.2 -u admin -p secret --format json

Prerequisites:
    pip install paramiko
    SSH must be enabled on target devices (Cisco IOS/IOS-XE supported).
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys
from datetime import datetime
from io import StringIO

import paramiko

LOG = logging.getLogger(__name__)


def build_ssh_client() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client


def run_command(shell, command: str, timeout: float = 10.0) -> str:
    shell.send(command + "\n")
    output = ""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(4096).decode("utf-8", errors="replace")
            output += chunk
            if re.search(r"[#>]\s*$", chunk):
                break
        time.sleep(0.1)
    return output


def parse_version(raw: str) -> dict:
    info = {}
    m = re.search(r"Cisco IOS(?:-XE)? Software.*?Version\s+(\S+)", raw)
    if m:
        info["version"] = m.group(1).rstrip(",")
    m = re.search(r"Technical Support.*?cisco\s+(\S+)\s+processor", raw, re.DOTALL | re.IGNORECASE)
    if m:
        info["platform"] = m.group(1)
    else:
        m = re.search(r"^cisco\s+(\S+)\s+", raw, re.MULTILINE | re.IGNORECASE)
        if m:
            info["platform"] = m.group(1)
    m = re.search(r"Processor board ID\s+(\S+)", raw)
    if m:
        info["serial"] = m.group(1)
    m = re.search(r"(\d+)K bytes of physical memory", raw)
    if m:
        info["ram_kb"] = int(m.group(1))
    m = re.search(r"uptime is (.+?)(?:\n|$)", raw, re.IGNORECASE)
    if m:
        info["uptime"] = m.group(1).strip()
    return info


def parse_inventory(raw: str) -> list:
    modules = []
    current = {}
    for line in raw.splitlines():
        name_m = re.match(r'^NAME:\s+"([^"]*)".*?DESCR:\s+"([^"]*)"', line)
        if name_m:
            current = {"name": name_m.group(1), "descr": name_m.group(2)}
        pid_m = re.match(r'^PID:\s+(\S*)\s+.*?SN:\s+(\S*)', line)
        if pid_m and current:
            current["pid"] = pid_m.group(1)
            current["sn"] = pid_m.group(2)
            modules.append(current)
            current = {}
    return modules


def collect_device_inventory(host: str, username: str, password: str, port: int = 22) -> dict:
    record = {"host": host, "timestamp": datetime.utcnow().isoformat(), "status": "error"}
    client = build_ssh_client()
    try:
        client.connect(host, port=port, username=username, password=password,
                       look_for_keys=False, allow_agent=False, timeout=15)
        shell = client.invoke_shell(width=200, height=50)
        import time; time.sleep(1)
        shell.recv(8192)  # discard banner/prompt

        run_command(shell, "terminal length 0")
        ver_output = run_command(shell, "show version")
        inv_output = run_command(shell, "show inventory")

        record.update(parse_version(ver_output))
        record["modules"] = parse_inventory(inv_output)
        record["status"] = "ok"
        LOG.info("Collected inventory from %s (platform=%s)", host, record.get("platform", "unknown"))
    except paramiko.AuthenticationException:
        LOG.error("Authentication failed for %s", host)
        record["error"] = "authentication_failed"
    except paramiko.SSHException as exc:
        LOG.error("SSH error on %s: %s", host, exc)
        record["error"] = str(exc)
    except OSError as exc:
        LOG.error("Connection error on %s: %s", host, exc)
        record["error"] = str(exc)
    finally:
        client.close()
    return record


def write_csv(records: list, path: str) -> None:
    fieldnames = ["host", "timestamp", "status", "platform", "version",
                  "serial", "ram_kb", "uptime", "error"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            row = {k: rec.get(k, "") for k in fieldnames}
            if rec.get("modules"):
                row["platform"] = row["platform"] or rec["modules"][0].get("pid", "")
            writer.writerow(row)
    LOG.info("CSV written to %s", path)


def write_json(records: list, path: str) -> None:
    with open(path, "w") as fh:
        json.dump(records, fh, indent=2)
    LOG.info("JSON written to %s", path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect hardware/software inventory from Cisco network devices."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--devices", help="Comma-separated list of device IPs/hostnames")
    group.add_argument("-f", "--file", help="File with one device IP/hostname per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--ask-pass", action="store_true", help="Always prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--output", default=None, help="Output file path (default: stdout summary)")
    parser.add_argument("--format", choices=["csv", "json"], default="csv",
                        help="Output format (default: csv)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.ask_pass or args.password is None:
        password = getpass.getpass(f"Password for {args.username}: ")
    else:
        password = args.password

    if args.devices:
        hosts = [h.strip() for h in args.devices.split(",") if h.strip()]
    else:
        try:
            with open(args.file) as fh:
                hosts = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except OSError as exc:
            LOG.error("Cannot read device file: %s", exc)
            return 1

    if not hosts:
        LOG.error("No devices specified.")
        return 1

    records = []
    for host in hosts:
        print(f"Connecting to {host} ...", end=" ", flush=True)
        rec = collect_device_inventory(host, args.username, password, args.port)
        status_label = "OK" if rec["status"] == "ok" else "FAILED"
        print(status_label)
        records.append(rec)

    output_path = args.output or f"inventory_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{args.format}"
    if args.format == "json":
        write_json(records, output_path)
    else:
        write_csv(records, output_path)

    ok = sum(1 for r in records if r["status"] == "ok")
    print(f"\nInventory complete: {ok}/{len(records)} devices successful. Output: {output_path}")
    return 0 if ok == len(records) else 2


if __name__ == "__main__":
    sys.exit(main())
```