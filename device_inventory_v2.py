The working directory is `/opt/NetAutoCommitter`, which is a different project — the paramiko-network-scripts repo isn't on this machine. Here's the script content as requested:

```
"""
vlan_table.py - Network Device VLAN Table Collector

Connects to a Cisco IOS/IOS-XE device via SSH and retrieves the active VLAN
database, parsing VLAN IDs, names, status, and assigned switchports.

Useful for auditing VLAN assignments, validating provisioning, and generating
switch documentation without screen-scraping manually.

Usage:
    python vlan_table.py -d 192.168.1.1 -u admin -p secret
    python vlan_table.py -d 192.168.1.1 -u admin --ask-pass
    python vlan_table.py -d 192.168.1.1 -u admin -p secret --output vlans.json
    python vlan_table.py -d 192.168.1.1 -u admin -p secret --format csv

Prerequisites:
    pip install paramiko
    SSH access enabled on the target device (ip ssh version 2)
    User account with at minimum read-only privilege (show commands)
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException as exc:
        raise RuntimeError(f"Authentication failed for {username}@{host}") from exc
    except paramiko.SSHException as exc:
        raise RuntimeError(f"SSH negotiation failed for {host}: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Network error reaching {host}: {exc}") from exc
    return client


def run_command(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        log.debug("stderr: %s", err.strip())
    return out


def parse_vlan_brief(raw):
    """Parse 'show vlan brief' into a list of VLAN dicts.

    IOS output format:
    VLAN  Name                             Status    Ports
    ----  -------------------------------- --------- -------------------------
    1     default                          active    Gi0/1, Gi0/2
    10    MGMT                             active    Gi0/3
    """
    vlans = []
    current = None
    in_data = False

    for line in raw.splitlines():
        if re.match(r"^-{4,}", line):
            in_data = True
            continue
        if not in_data or not line.strip():
            continue

        m = re.match(
            r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|suspended|act/lshut)\s*(.*)?$",
            line,
        )
        if m:
            ports = [p.strip() for p in m.group(4).split(",") if p.strip()]
            current = {
                "vlan_id": int(m.group(1)),
                "name": m.group(2),
                "status": m.group(3),
                "ports": ports,
            }
            vlans.append(current)
        elif current and line.startswith(" "):
            more = [p.strip() for p in line.split(",") if p.strip()]
            current["ports"].extend(more)

    return vlans


def print_table(vlans):
    if not vlans:
        print("No VLANs found.")
        return
    print(f"{'VLAN':<6} {'Name':<32} {'Status':<12} Ports")
    print("-" * 80)
    for v in vlans:
        ports = ", ".join(v["ports"])
        print(f"{v['vlan_id']:<6} {v['name']:<32} {v['status']:<12} {ports}")
    print(f"\nTotal: {len(vlans)} VLANs")


def write_json(vlans, path):
    with open(path, "w") as f:
        json.dump(vlans, f, indent=2)
    print(f"Saved {len(vlans)} VLANs to {path}")


def write_csv(vlans, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["vlan_id", "name", "status", "ports"])
        writer.writeheader()
        for v in vlans:
            writer.writerow({**v, "ports": ", ".join(v["ports"])})
    print(f"Saved {len(vlans)} VLANs to {path}")


def build_parser():
    p = argparse.ArgumentParser(
        description="Retrieve and display the VLAN table from a Cisco IOS/IOS-XE device"
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP address")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--ask-pass", action="store_true", help="Prompt for password interactively")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")
    p.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format for stdout (default: table)",
    )
    p.add_argument("--output", default=None, help="Save results to file (.json or .csv)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or password is None:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    log.debug("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(args.device, args.username, password, args.port, args.timeout)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        log.debug("Running 'show vlan brief'")
        raw = run_command(client, "show vlan brief")
    except Exception as exc:
        print(f"ERROR: Command failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

    vlans = parse_vlan_brief(raw)

    if not vlans:
        print(
            "No VLANs parsed. Verify the device supports 'show vlan brief' "
            "(Layer 2 switch required).",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.output:
        if args.output.endswith(".csv"):
            write_csv(vlans, args.output)
        else:
            write_json(vlans, args.output)
    elif args.format == "json":
        print(json.dumps(vlans, indent=2))
    elif args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=["vlan_id", "name", "status", "ports"])
        writer.writeheader()
        for v in vlans:
            writer.writerow({**v, "ports": ", ".join(v["ports"])})
    else:
        print_table(vlans)
```