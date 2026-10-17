```python
"""
hardware_inventory.py - Network device hardware component inventory collector.

Connects to a Cisco IOS/IOS-XE/NX-OS device over SSH and collects detailed
hardware component data including chassis, line cards, power supplies, fans,
and transceivers with their serial numbers and product IDs.

Useful for asset tracking, RMA processing, and compliance audits where you
need per-component serial numbers rather than just the device-level inventory.

Usage:
    python hardware_inventory.py -H 192.168.1.1 -u admin -p secret
    python hardware_inventory.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python hardware_inventory.py -H 192.168.1.1 -u admin -p secret -o inv.json
    python hardware_inventory.py -H 192.168.1.1 -u admin -p secret --no-raw

Prerequisites:
    pip install paramiko
    SSH access with privileges for 'show inventory' and 'show version'
"""

import argparse
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
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_file),
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        log.debug("stderr for %r: %s", command, err.strip())
    return output


def parse_show_inventory(raw):
    """Parse IOS/IOS-XE/NX-OS 'show inventory' into a list of component dicts."""
    components = []
    pattern = re.compile(
        r'NAME:\s+"([^"]*)"[^\n]*\n'
        r'DESCR:\s+"([^"]*)"[^\n]*\n'
        r'PID:\s*(\S*)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S*)',
        re.MULTILINE,
    )
    for m in pattern.finditer(raw):
        name, descr, pid, vid, sn = (g.strip() for g in m.groups())
        if not pid and not sn:
            continue
        components.append({
            "name": name,
            "description": descr,
            "product_id": pid or "N/A",
            "version_id": vid or "N/A",
            "serial_number": sn or "N/A",
        })
    return components


def parse_show_version(raw):
    """Extract device-level context from 'show version' output."""
    fields = {
        "hostname": r"^(\S+)\s+uptime",
        "software_version": r"(?:Cisco IOS[^\n]*Version|Version)\s+([^\s,]+)",
        "uptime": r"uptime is (.+?)$",
        "platform": r"^[Cc]isco\s+([\w\-]+)\s+\(",
        "serial_number": r"Processor board ID\s+(\S+)",
        "total_ram_kb": r"(\d+)K bytes of physical memory",
    }
    info = {}
    for key, pat in fields.items():
        m = re.search(pat, raw, re.MULTILINE | re.IGNORECASE)
        if m:
            info[key] = m.group(1).strip()
    return info


def collect(client, host):
    log.info("Running 'show inventory' on %s", host)
    inv_raw = run_command(client, "show inventory")
    components = parse_show_inventory(inv_raw)
    log.info("Found %d hardware components", len(components))

    log.info("Running 'show version' on %s", host)
    ver_raw = run_command(client, "show version")
    device_info = parse_show_version(ver_raw)

    return {
        "host": host,
        "collected_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device_info": device_info,
        "component_count": len(components),
        "components": components,
        "raw": {
            "show_inventory": inv_raw,
            "show_version": ver_raw,
        },
    }


def build_parser():
    p = argparse.ArgumentParser(
        description="Collect hardware component inventory from a network device"
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("-k", "--key", dest="key_file", default=None,
                   help="Path to SSH private key")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30,
                   help="SSH connection timeout in seconds")
    p.add_argument("-o", "--output", default=None,
                   help="Write JSON to file instead of stdout")
    p.add_argument("--no-raw", action="store_true",
                   help="Exclude raw command output from JSON result")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging")
    return p


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        log.error("One of --password or --key is required")
        sys.exit(1)

    try:
        client = ssh_connect(
            host=args.host,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Cannot connect to %s: %s", args.host, exc)
        sys.exit(1)

    try:
        result = collect(client, args.host)
    except Exception as exc:
        log.error("Collection failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    if args.no_raw:
        result.pop("raw", None)

    payload = json.dumps(result, indent=2)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(payload)
            log.info("Wrote inventory to %s (%d components)",
                     args.output, result["component_count"])
        except OSError as exc:
            log.error("Failed to write output file: %s", exc)
            sys.exit(1)
    else:
        print(payload)


if __name__ == "__main__":
    main()
```