"""
device_inventory.py - Network Device Inventory Collector

Purpose:
    Connects to one or more Cisco IOS/IOS-XE devices via SSH and collects
    hardware and software inventory data (hostname, model, serial number,
    IOS version, uptime). Results are written to CSV and optionally printed
    as a formatted table.

Usage:
    Single device:
        python device_inventory.py -d 192.168.1.1 -u admin -p secret

    Multiple devices from file (one IP per line):
        python device_inventory.py -f devices.txt -u admin -p secret -o inventory.csv

    With SSH key:
        python device_inventory.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa

Prerequisites:
    pip install paramiko
"""

import argparse
import csv
import logging
import re
import sys
import time
from dataclasses import dataclass, fields
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class DeviceRecord:
    host: str
    hostname: str
    model: str
    serial: str
    ios_version: str
    uptime: str
    status: str


def ssh_send(shell, command: str, wait: float = 1.5) -> str:
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode("utf-8", errors="replace")
    return output


def collect_inventory(host: str, username: str, password: str = None,
                      key_path: str = None, port: int = 22,
                      timeout: int = 15) -> DeviceRecord:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(1)
        shell.recv(65535)  # drain banner

        ssh_send(shell, "terminal length 0", wait=0.5)
        version_output = ssh_send(shell, "show version", wait=2.0)
        inventory_output = ssh_send(shell, "show inventory", wait=2.0)
        client.close()

        hostname = _parse_hostname(version_output)
        model = _parse_model(version_output, inventory_output)
        serial = _parse_serial(version_output, inventory_output)
        ios_version = _parse_version(version_output)
        uptime = _parse_uptime(version_output)

        return DeviceRecord(
            host=host,
            hostname=hostname,
            model=model,
            serial=serial,
            ios_version=ios_version,
            uptime=uptime,
            status="ok",
        )

    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
        return DeviceRecord(host=host, hostname="", model="", serial="",
                            ios_version="", uptime="", status="auth_failed")
    except (paramiko.SSHException, OSError) as exc:
        log.error("%s: connection error: %s", host, exc)
        return DeviceRecord(host=host, hostname="", model="", serial="",
                            ios_version="", uptime="", status=f"error: {exc}")
    finally:
        client.close()


def _parse_hostname(output: str) -> str:
    m = re.search(r"^(\S+)\s+uptime is", output, re.MULTILINE)
    return m.group(1) if m else ""


def _parse_model(version_output: str, inventory_output: str) -> str:
    m = re.search(r"[Cc]isco\s+(\S+)\s+\(", version_output)
    if m:
        return m.group(1)
    m = re.search(r'NAME:.*?PID:\s*(\S+)', inventory_output)
    return m.group(1) if m else ""


def _parse_serial(version_output: str, inventory_output: str) -> str:
    m = re.search(r"[Pp]rocessor board ID\s+(\S+)", version_output)
    if m:
        return m.group(1)
    m = re.search(r'SN:\s*(\S+)', inventory_output)
    return m.group(1) if m else ""


def _parse_version(output: str) -> str:
    m = re.search(r"[Cc]isco IOS.*?Version\s+([\d().A-Za-z]+)", output)
    return m.group(1) if m else ""


def _parse_uptime(output: str) -> str:
    m = re.search(r"uptime is (.+)", output)
    return m.group(1).strip() if m else ""


def print_table(records: list[DeviceRecord]) -> None:
    col_widths = {f.name: len(f.name) for f in fields(DeviceRecord)}
    for rec in records:
        for f in fields(DeviceRecord):
            col_widths[f.name] = max(col_widths[f.name], len(str(getattr(rec, f.name))))

    header = "  ".join(name.upper().ljust(col_widths[name]) for name in col_widths)
    print(header)
    print("-" * len(header))
    for rec in records:
        row = "  ".join(str(getattr(rec, f.name)).ljust(col_widths[f.name])
                        for f in fields(DeviceRecord))
        print(row)


def write_csv(records: list[DeviceRecord], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=[f.name for f in fields(DeviceRecord)])
        writer.writeheader()
        for rec in records:
            writer.writerow({f.name: getattr(rec, f.name) for f in fields(DeviceRecord)})
    log.info("Inventory written to %s", path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect hardware/software inventory from Cisco IOS devices."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("-f", "--file", help="File containing device IPs, one per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout in seconds")
    parser.add_argument("-o", "--output", default=None, help="CSV output file path")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if not args.password and not args.key:
        import getpass
        args.password = getpass.getpass("SSH password: ")

    hosts = []
    if args.device:
        hosts = [args.device]
    else:
        path = Path(args.file)
        if not path.exists():
            log.error("Device file not found: %s", args.file)
            sys.exit(1)
        hosts = [line.strip() for line in path.read_text().splitlines()
                 if line.strip() and not line.startswith("#")]

    log.info("Collecting inventory from %d device(s)...", len(hosts))
    records = []
    for host in hosts:
        log.info("Connecting to %s", host)
        record = collect_inventory(
            host=host,
            username=args.username,
            password=args.password,
            key_path=args.key,
            port=args.port,
            timeout=args.timeout,
        )
        records.append(record)

    print_table(records)

    if args.output:
        write_csv(records, args.output)

    failed = sum(1 for r in records if r.status != "ok")
    if failed:
        log.warning("%d device(s) failed", failed)
        sys.exit(1)