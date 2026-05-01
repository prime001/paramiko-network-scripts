```python
"""
vlan_audit.py — VLAN membership and trunk audit via SSH (Cisco IOS/IOS-XE)

Purpose:
    Collects VLAN database, port assignments, and trunk links from a Cisco
    switch. Outputs a structured report to stdout and optionally to JSON.

Usage:
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret
    python vlan_audit.py -d 192.168.1.1 -u admin --ask-pass --json-out vlans.json

Prerequisites:
    pip install paramiko
    Target device must have SSH enabled and the user needs privilege level 1+.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr for '%s': %s", command, err)
    return output


def parse_vlan_brief(raw: str) -> dict:
    """Return {vlan_id: {'name': str, 'status': str, 'ports': [str]}}."""
    vlans = {}
    current_id = None
    for line in raw.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+(active|act/unsup|suspended)\s*(.*)?$", line)
        if m:
            vid, name, status, ports_str = m.groups()
            current_id = vid
            vlans[vid] = {
                "name": name,
                "status": status,
                "ports": [p.strip() for p in ports_str.split(",") if p.strip()],
            }
        elif current_id and re.match(r"^\s{10,}", line):
            extra = [p.strip() for p in line.split(",") if p.strip()]
            vlans[current_id]["ports"].extend(extra)
    return vlans


def parse_trunk_ports(raw: str) -> dict:
    """Return {interface: {'mode': str, 'encap': str, 'native': str, 'vlans': str}}."""
    trunks = {}
    section = None
    for line in raw.splitlines():
        if re.match(r"^Port\s+Mode\s+Encapsulation", line):
            section = "mode"
            continue
        if re.match(r"^Port\s+Vlans allowed on trunk", line):
            section = "allowed"
            continue
        if re.match(r"^Port\s+Vlans allowed and active", line):
            section = "active"
            continue
        if not line.strip() or line.startswith("-"):
            continue
        parts = line.split()
        if not parts:
            continue
        iface = parts[0]
        if section == "mode" and len(parts) >= 3:
            trunks.setdefault(iface, {})
            trunks[iface]["mode"] = parts[1]
            trunks[iface]["encap"] = parts[2]
            trunks[iface]["native"] = parts[4] if len(parts) > 4 else "1"
        elif section == "allowed" and iface in trunks:
            trunks[iface]["vlans_allowed"] = parts[1] if len(parts) > 1 else ""
        elif section == "active" and iface in trunks:
            trunks[iface]["vlans_active"] = parts[1] if len(parts) > 1 else ""
    return trunks


def build_client(host: str, port: int, username: str, password: str,
                 timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def print_report(vlans: dict, trunks: dict, host: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  VLAN Audit — {host}")
    print(f"{'=' * 60}")
    print(f"\n{'ID':<8}{'Name':<24}{'Status':<14}Ports")
    print("-" * 60)
    for vid in sorted(vlans, key=lambda x: int(x)):
        v = vlans[vid]
        ports = ", ".join(v["ports"]) or "(none)"
        print(f"{vid:<8}{v['name']:<24}{v['status']:<14}{ports}")

    if trunks:
        print(f"\n{'Trunk Interfaces':^60}")
        print("-" * 60)
        print(f"{'Interface':<18}{'Mode':<12}{'Native':<10}Active VLANs")
        print("-" * 60)
        for iface, t in sorted(trunks.items()):
            active = t.get("vlans_active", t.get("vlans_allowed", ""))
            print(f"{iface:<18}{t.get('mode',''):<12}{t.get('native',''):<10}{active}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit VLANs and trunk ports on a Cisco switch via SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout")
    parser.add_argument("--json-out", metavar="FILE", help="Write results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or not password:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        log.info("Connecting to %s:%d", args.device, args.port)
        client = build_client(args.device, args.port, args.username, password,
                               args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        log.info("Collecting VLAN data")
        raw_vlans = ssh_exec(client, "show vlan brief", args.timeout)
        raw_trunks = ssh_exec(client, "show interfaces trunk", args.timeout)
    except Exception as exc:
        log.error("Command execution failed: %s", exc)
        client.close()
        sys.exit(1)
    finally:
        client.close()

    vlans = parse_vlan_brief(raw_vlans)
    trunks = parse_trunk_ports(raw_trunks)

    if not vlans:
        log.warning("No VLANs parsed — output may be in an unexpected format")

    print_report(vlans, trunks, args.device)

    if args.json_out:
        payload = {"device": args.device, "vlans": vlans, "trunks": trunks}
        with open(args.json_out, "w") as fh:
            json.dump(payload, fh, indent=2)
        log.info("Results written to %s", args.json_out)


if __name__ == "__main__":
    main()
```