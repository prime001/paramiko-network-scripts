hardware_inventory.py - Network Hardware Asset Inventory Collector

Purpose:
    Collects hardware asset data (chassis model, serial numbers, installed modules,
    software version, uptime) from Cisco IOS devices via SSH. Produces a structured
    JSON or CSV report suitable for asset management and lifecycle tracking.

Usage:
    Single device:
        python hardware_inventory.py --host 192.168.1.1 --username admin --password secret

    Multiple devices from file:
        python hardware_inventory.py --hosts-file devices.txt --username admin --key-file ~/.ssh/id_rsa

    CSV output:
        python hardware_inventory.py --host 192.168.1.1 --format csv --output inventory.csv

Prerequisites:
    pip install paramiko

    devices.txt format: one IP or hostname per line; lines starting with # are skipped.
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys
from datetime import datetime

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
        kwargs["look_for_keys"] = True
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError(f"{host}: password or key_file required")
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=30):
    _, stdout, _ = client.exec_command(command, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


def parse_show_version(output):
    data = {
        "hostname": None,
        "platform": None,
        "ios_version": None,
        "uptime": None,
        "serial_number": None,
        "reload_reason": None,
    }
    m = re.search(r"^(\S+)\s+uptime is (.+)$", output, re.MULTILINE)
    if m:
        data["hostname"] = m.group(1)
        data["uptime"] = m.group(2).strip()

    m = re.search(r"Cisco IOS.*?Version\s+([\S]+)", output)
    if m:
        data["ios_version"] = m.group(1).rstrip(",")

    m = re.search(r"cisco\s+(\S+[^\s(]+)\s+\(", output, re.IGNORECASE)
    if m:
        data["platform"] = m.group(1)

    m = re.search(r"[Pp]rocessor board ID\s+(\S+)", output)
    if m:
        data["serial_number"] = m.group(1)

    m = re.search(r"[Ll]ast reload reason:\s*(.+)$", output, re.MULTILINE)
    if m:
        data["reload_reason"] = m.group(1).strip()

    return data


def parse_show_inventory(output):
    modules = []
    current = {}
    for line in output.splitlines():
        name_m = re.match(r'^NAME:\s+"([^"]+)",\s+DESCR:\s+"([^"]+)"', line)
        pid_m = re.match(r"^PID:\s+(\S*)\s*,\s*VID:\s+(\S*)\s*,\s*SN:\s+(\S*)", line)
        if name_m:
            if current:
                modules.append(current)
            current = {"name": name_m.group(1), "description": name_m.group(2)}
        elif pid_m and current:
            current["pid"] = pid_m.group(1)
            current["vid"] = pid_m.group(2)
            current["sn"] = pid_m.group(3)
    if current:
        modules.append(current)
    return modules


def collect_device(host, username, password=None, key_file=None, port=22):
    result = {
        "host": host,
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "status": "error",
        "error": None,
        "version_info": {},
        "inventory_modules": [],
    }
    client = None
    try:
        logger.info("Connecting to %s", host)
        client = ssh_connect(host, username, password, key_file, port)
        result["version_info"] = parse_show_version(run_command(client, "show version"))
        result["inventory_modules"] = parse_show_inventory(
            run_command(client, "show inventory")
        )
        result["status"] = "ok"
        logger.info(
            "%s: %d inventory entries collected", host, len(result["inventory_modules"])
        )
    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed"
        logger.error("%s: authentication failed", host)
    except paramiko.SSHException as exc:
        result["error"] = f"SSH error: {exc}"
        logger.error("%s: SSH error: %s", host, exc)
    except OSError as exc:
        result["error"] = f"Connection error: {exc}"
        logger.error("%s: connection error: %s", host, exc)
    finally:
        if client:
            client.close()
    return result


def write_json(results, path):
    with open(path, "w") as fh:
        json.dump(results, fh, indent=2)
    logger.info("JSON written to %s", path)


def write_csv(results, path):
    rows = []
    for r in results:
        vi = r.get("version_info", {})
        base = {
            "host": r["host"],
            "status": r["status"],
            "collected_at": r["collected_at"],
            "hostname": vi.get("hostname", ""),
            "platform": vi.get("platform", ""),
            "ios_version": vi.get("ios_version", ""),
            "serial_number": vi.get("serial_number", ""),
            "uptime": vi.get("uptime", ""),
            "reload_reason": vi.get("reload_reason", ""),
            "error": r.get("error", ""),
        }
        modules = r.get("inventory_modules", [])
        if modules:
            for mod in modules:
                row = dict(base)
                row.update(
                    {
                        "module_name": mod.get("name", ""),
                        "module_desc": mod.get("description", ""),
                        "module_pid": mod.get("pid", ""),
                        "module_sn": mod.get("sn", ""),
                    }
                )
                rows.append(row)
        else:
            rows.append(base)

    if not rows:
        return

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    logger.info("CSV written to %s", path)


def load_hosts_file(path):
    hosts = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def build_parser():
    p = argparse.ArgumentParser(
        description="Collect hardware asset inventory from network devices via SSH"
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP or hostname")
    target.add_argument(
        "--hosts-file", metavar="FILE", help="File with one host per line"
    )
    p.add_argument("--username", required=True, help="SSH username")
    auth = p.add_mutually_exclusive_group()
    auth.add_argument("--password", help="SSH password")
    auth.add_argument("--key-file", metavar="FILE", help="Path to SSH private key")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--format", choices=["json", "csv"], default="json", help="Output format"
    )
    p.add_argument(
        "--output", metavar="FILE", help="Output file (default: stdout for JSON)"
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}: ")

    hosts = [args.host] if args.host else load_hosts_file(args.hosts_file)
    if not hosts:
        logger.error("No hosts to process")
        sys.exit(1)

    results = [
        collect_device(
            host=host,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
        )
        for host in hosts
    ]

    if args.format == "json":
        if args.output:
            write_json(results, args.output)
        else:
            print(json.dumps(results, indent=2))
    else:
        out = args.output or (
            f"hardware_inventory_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        write_csv(results, out)

    failed = sum(1 for r in results if r["status"] != "ok")
    if failed:
        logger.warning("%d/%d device(s) failed", failed, len(results))
        sys.exit(1)