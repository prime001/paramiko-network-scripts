```python
"""
hardware_inventory.py - Physical hardware asset inventory via SSH.

Collects chassis component data (serial numbers, part numbers, descriptions)
from Cisco IOS/IOS-XE/NX-OS devices using `show inventory`. Intended for
asset management, RMA tracking, and warranty lookups — distinct from
device_inventory.py which captures OS-level attributes (hostname, version,
uptime).

Usage:
    python hardware_inventory.py -d 192.168.1.1 -u admin -p secret
    python hardware_inventory.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa --format json
    python hardware_inventory.py -d 192.168.1.1 -u admin -p secret -o assets.csv

Prerequisites:
    pip install paramiko
    SSH access to target device with at minimum privilege level 1.
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys
from datetime import datetime, timezone

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def ssh_connect(host, port, username, password=None, key_file=None, timeout=30):
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
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide either --password or --key-file")
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def parse_inventory(raw):
    """Parse IOS/IOS-XE/NX-OS `show inventory` stanzas into dicts."""
    pattern = re.compile(
        r'NAME:\s*"([^"]*)"[^,\n]*,\s*DESCR:\s*"([^"]*)"\s*\n'
        r'PID:\s*(\S*)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S*)',
        re.MULTILINE,
    )
    return [
        {
            "name": m.group(1).strip(),
            "description": m.group(2).strip(),
            "pid": m.group(3).strip(),
            "vid": m.group(4).strip(),
            "serial": m.group(5).strip(),
        }
        for m in pattern.finditer(raw)
    ]


def collect(client, device):
    log.info("Pulling inventory from %s", device)
    raw = run_command(client, "show inventory")
    if not raw.strip():
        log.warning("Empty output — device may not support 'show inventory'")
        return []
    entries = parse_inventory(raw)
    if not entries:
        log.warning("Parsed 0 entries; raw output may use an unsupported format")
        log.debug("Raw:\n%s", raw)
        return []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for e in entries:
        e["device"] = device
        e["collected_at"] = ts
    log.info("Found %d hardware component(s)", len(entries))
    return entries


def print_table(entries):
    if not entries:
        print("No inventory entries found.")
        return
    rows = [{"name": "Name", "description": "Description", "pid": "PID",
             "vid": "VID", "serial": "Serial"}] + entries
    w = {k: max(len(str(r.get(k, ""))) for r in rows)
         for k in ("name", "description", "pid", "vid", "serial")}
    w["description"] = min(w["description"], 42)
    fmt = (f"{{name:<{w['name']}}}  {{description:<{w['description']}}}  "
           f"{{pid:<{w['pid']}}}  {{vid:<{w['vid']}}}  {{serial:<{w['serial']}}}")
    header = fmt.format(name="Name", description="Description",
                        pid="PID", vid="VID", serial="Serial")
    print(header)
    print("-" * len(header))
    for e in entries:
        print(fmt.format(
            name=e["name"],
            description=e["description"][:w["description"]],
            pid=e["pid"],
            vid=e["vid"],
            serial=e["serial"],
        ))


FIELDS = ["device", "name", "description", "pid", "vid", "serial", "collected_at"]


def write_csv(entries, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(entries)
    log.info("Wrote %d rows to %s", len(entries), path)


def write_json(entries, path):
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)
    log.info("Wrote %d entries to %s", len(entries), path)


def build_parser():
    p = argparse.ArgumentParser(
        description="Collect hardware component inventory (PIDs, serial numbers) via SSH."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("-k", "--key-file", default=None, dest="key_file",
                   help="Path to SSH private key")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table",
                   help="Output format when writing to stdout (default: table)")
    p.add_argument("-o", "--output", default=None,
                   help="Write output to file; extension (.csv/.json) sets format")
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    client = None
    try:
        log.info("Connecting to %s:%d", args.device, args.port)
        client = ssh_connect(
            host=args.device,
            port=args.port,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            timeout=args.timeout,
        )
        entries = collect(client, args.device)

        if args.output:
            if args.output.lower().endswith(".json"):
                write_json(entries, args.output)
            else:
                write_csv(entries, args.output)
        elif args.format == "json":
            print(json.dumps(entries, indent=2))
        elif args.format == "csv":
            writer = csv.DictWriter(sys.stdout, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(entries)
        else:
            print_table(entries)

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Network error connecting to %s: %s", args.device, exc)
        sys.exit(1)
    finally:
        if client:
            client.close()
```