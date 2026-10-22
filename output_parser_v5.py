```python
"""
vlan_audit.py - Cisco IOS/IOS-XE VLAN database auditor via SSH.

Connects to a switch, retrieves 'show vlan brief', and reports VLAN names,
status, port assignments, and flags active VLANs with no assigned ports.
Useful for periodic VLAN hygiene audits and change-management baselines.

Usage:
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret
    python vlan_audit.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret --unused-only
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret --json

Prerequisites:
    pip install paramiko
"""

import argparse
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def ssh_connect(host, port, username, password=None, key_path=None, timeout=30):
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
    if key_path:
        kwargs["key_filename"] = key_path
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide password or key_path")
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr for %r: %s", command, err)
    return output


def parse_vlan_brief(output):
    """Parse 'show vlan brief' into a list of VLAN dicts."""
    vlans = []
    header_seen = False
    current_vlan = None

    for line in output.splitlines():
        if re.match(r"^VLAN\s+Name\s+Status", line):
            header_seen = True
            continue
        if not header_seen or re.match(r"^-{4}", line):
            continue

        m = re.match(
            r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|suspend|act/lshut)\s*(.*)",
            line,
        )
        if m:
            ports_raw = m.group(4).strip()
            ports = [p.strip() for p in re.split(r",\s*", ports_raw) if p.strip()]
            current_vlan = {
                "vlan_id": int(m.group(1)),
                "name": m.group(2),
                "status": m.group(3),
                "ports": ports,
            }
            vlans.append(current_vlan)
        elif current_vlan is not None and line and line[0] == " ":
            extra = [p.strip() for p in re.split(r",\s*", line.strip()) if p.strip()]
            current_vlan["ports"].extend(extra)
        else:
            current_vlan = None

    return vlans


def print_table(vlans):
    col_id = 6
    col_name = 32
    col_status = 12
    col_ports = 38
    header = (
        f"{'ID':<{col_id}} {'Name':<{col_name}} "
        f"{'Status':<{col_status}} {'Ports':<{col_ports}} Unused"
    )
    print(header)
    print("-" * len(header))
    for v in vlans:
        unused = "YES" if not v["ports"] and v["status"] == "active" else ""
        ports_str = ", ".join(v["ports"][:5])
        if len(v["ports"]) > 5:
            ports_str += f" +{len(v['ports']) - 5} more"
        print(
            f"{v['vlan_id']:<{col_id}} {v['name']:<{col_name}} "
            f"{v['status']:<{col_status}} {ports_str:<{col_ports}} {unused}"
        )


def build_parser():
    p = argparse.ArgumentParser(
        description="Audit VLAN database on a Cisco IOS/IOS-XE switch via SSH."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--key", dest="key_path", default=None, help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--unused-only",
        action="store_true",
        help="Show only active VLANs with no assigned ports",
    )
    p.add_argument("--json", action="store_true", help="Output as JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_path:
        parser.error("Provide --password or --key for authentication")

    log.debug("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        client = ssh_connect(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            key_path=args.key_path,
        )
    except paramiko.AuthenticationException:
        print(
            f"ERROR: Authentication failed for {args.username}@{args.host}",
            file=sys.stderr,
        )
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        print(f"ERROR: Cannot connect to {args.host}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = run_command(client, "show vlan brief")
    except Exception as exc:
        print(f"ERROR: Command execution failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

    vlans = parse_vlan_brief(raw)
    if not vlans:
        print(
            "No VLAN data parsed. Verify this is a Cisco IOS/IOS-XE switch.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.unused_only:
        vlans = [v for v in vlans if not v["ports"] and v["status"] == "active"]

    if args.json:
        print(json.dumps(vlans, indent=2))
        sys.exit(0)

    unused_count = sum(1 for v in vlans if not v["ports"] and v["status"] == "active")
    print(f"\nVLAN Audit — {args.host}")
    print(f"Total VLANs: {len(vlans)}  |  Unused active VLANs: {unused_count}\n")
    print_table(vlans)
```