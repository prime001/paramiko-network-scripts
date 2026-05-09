hardware_inventory.py - Collect physical hardware inventory from Cisco network devices.

Queries `show version` and `show inventory` to extract chassis serial numbers,
hardware module PIDs/VIDs, installed memory, and flash capacity.  Distinct from
device_inventory.py (which captures OS/uptime/config metadata): this script targets
physical asset tracking, rack audits, and RMA prep workflows.

Usage:
    python hardware_inventory.py -H 192.168.1.1 -u admin -p secret
    python hardware_inventory.py --hosts devices.txt -u admin --key ~/.ssh/id_rsa
    python hardware_inventory.py -H 10.0.0.1 -u admin -p secret --format json -o out.json

Prerequisites:
    pip install paramiko
    SSH access to Cisco IOS / IOS-XE / NX-OS devices.
    'terminal length 0' is sent automatically; enable privilege not required for show cmds.
"""

import argparse
import csv
import getpass
import json
import logging
import re
import socket
import sys
from datetime import datetime, timezone

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)-8s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


def _ssh_connect(host, port, username, password, key_file, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username, timeout=timeout,
                  look_for_keys=False, allow_agent=False)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _run(client, command, timeout=20):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        logger.debug("stderr (%s): %s", command, err)
    return out


def _parse_version(output):
    data = {}
    m = re.search(r"^(\S+)\s+uptime is", output, re.MULTILINE)
    if m:
        data["hostname"] = m.group(1)
    m = re.search(r"Version\s+([\d\w()./:]+)", output)
    if m:
        data["ios_version"] = m.group(1)
    m = re.search(r"Processor board ID\s+(\S+)", output)
    if m:
        data["chassis_serial"] = m.group(1)
    m = re.search(r"(\d+)[Kk] bytes of physical memory", output)
    if not m:
        m = re.search(r"(\d+)[Kk]/\d+[Kk] bytes of memory", output)
    if m:
        data["memory_kb"] = int(m.group(1))
    m = re.search(r"(\d+)[Kk] bytes of.*?[Ff]lash", output)
    if m:
        data["flash_kb"] = int(m.group(1))
    m = re.search(r"(?:cisco\s+)([\w-]+)\s+(?:processor|chassis|with)", output, re.IGNORECASE)
    if m:
        data["platform"] = m.group(1)
    return data


def _parse_inventory(output):
    modules = []
    for block in re.split(r"\n(?=NAME:)", output):
        item = {}
        for field, pattern in [("name", r'NAME:\s+"([^"]+)"'),
                                ("descr", r'DESCR:\s+"([^"]+)"'),
                                ("pid", r'PID:\s+(\S+)'),
                                ("vid", r'VID:\s+(\S+)'),
                                ("sn", r'SN:\s+(\S+)')]:
            m = re.search(pattern, block)
            if m:
                item[field] = m.group(1).strip()
        if item.get("sn") and item.get("pid") and item["pid"] != "":
            modules.append(item)
    return modules


def collect(host, port, username, password, key_file, timeout):
    result = {
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error": None,
        "modules": [],
    }
    logger.info("Connecting to %s", host)
    try:
        client = _ssh_connect(host, port, username, password, key_file, timeout)
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error, OSError) as exc:
        logger.error("%s: connection failed — %s", host, exc)
        result["error"] = str(exc)
        return result

    try:
        _run(client, "terminal length 0")
        result.update(_parse_version(_run(client, "show version")))
        result["modules"] = _parse_inventory(_run(client, "show inventory"))
        logger.info("%s: collected %d modules", host, len(result["modules"]))
    except Exception as exc:
        logger.error("%s: command error — %s", host, exc)
        result["error"] = str(exc)
    finally:
        client.close()
    return result


def _print_table(results):
    cols = ["host", "hostname", "platform", "ios_version", "chassis_serial", "memory_kb", "flash_kb"]
    headers = ["Host", "Hostname", "Platform", "Version", "Chassis S/N", "Mem(KB)", "Flash(KB)"]
    rows = [[str(r.get(c, "")) for c in cols] for r in results]
    widths = [max(len(h), max((len(row[i]) for row in rows), default=0))
              for i, h in enumerate(headers)]
    sep = "  ".join("-" * w for w in widths)
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(sep)
    for r, row in zip(results, rows):
        print(fmt.format(*row))
        for mod in r.get("modules", []):
            print(f"    ├─ {mod.get('name',''):<24} PID:{mod.get('pid',''):<20} "
                  f"SN:{mod.get('sn',''):<16} VID:{mod.get('vid','')}")


def _write_csv(results, fh):
    top_fields = ["host", "hostname", "platform", "ios_version",
                  "chassis_serial", "memory_kb", "flash_kb", "error"]
    w = csv.DictWriter(fh, fieldnames=top_fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(results)


def main():
    parser = argparse.ArgumentParser(
        description="Collect hardware inventory (show version + show inventory) from Cisco devices."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-H", "--host", help="Single device IP/hostname")
    target.add_argument("--hosts", metavar="FILE", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", metavar="FILE", dest="key_file", help="SSH private key")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=10, help="SSH connect timeout (default: 10)")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write to file instead of stdout")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass("SSH password: ")

    if args.host:
        hosts = [args.host]
    else:
        try:
            with open(args.hosts) as fh:
                hosts = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as exc:
            logger.error("Cannot read hosts file: %s", exc)
            sys.exit(1)

    results = [collect(h, args.port, args.username, args.password,
                       args.key_file, args.timeout) for h in hosts]

    fh = open(args.output, "w") if args.output else sys.stdout
    try:
        if args.format == "json":
            json.dump(results, fh, indent=2)
            fh.write("\n")
        elif args.format == "csv":
            _write_csv(results, fh)
        else:
            _print_table(results)
    finally:
        if args.output:
            fh.close()

    failed = sum(1 for r in results if r["error"])
    if failed:
        logger.warning("%d/%d devices failed", failed, len(results))
        sys.exit(1)


if __name__ == "__main__":
    main()