```python
"""
vlan_audit.py - VLAN consistency audit for Cisco IOS/IOS-XE switches

Purpose:
    Connects to a Cisco switch via SSH and audits VLAN health:
      - Lists all defined VLANs with port assignments
      - Identifies trunk ports and their allowed/active VLAN sets
      - Flags orphaned VLANs (active in database but no assigned access ports)
      - Reports trunk ports carrying VLANs not defined in the local VLAN database

Usage:
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret
    python vlan_audit.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret --orphans --json

Prerequisites:
    pip install paramiko
    SSH enabled on device; user needs privilege level 1 or higher.
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import paramiko

log = logging.getLogger(__name__)


@dataclass
class VlanInfo:
    vlan_id: int
    name: str
    status: str
    ports: List[str] = field(default_factory=list)


@dataclass
class TrunkPort:
    interface: str
    native_vlan: int
    allowed_vlans: List[int] = field(default_factory=list)
    active_vlans: List[int] = field(default_factory=list)


def ssh_connect(
    host: str,
    username: str,
    password: Optional[str],
    key_path: Optional[str],
    port: int,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(hostname=host, port=port, username=username, timeout=30)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def run_command(client: paramiko.SSHClient, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=30)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr for %r: %s", command, err)
    return output


def expand_vlan_range(range_str: str) -> List[int]:
    vlans = []
    for part in range_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            vlans.extend(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            vlans.append(int(part))
    return vlans


def parse_vlan_brief(output: str) -> Dict[int, VlanInfo]:
    vlans: Dict[int, VlanInfo] = {}
    row_re = re.compile(
        r"^(\d+)\s+(\S+)\s+(active|act/lshut|act/unsup|suspended|sus/lshut)\s*(.*)?$"
    )
    cont_re = re.compile(r"^\s{20,}(\S.*)$")
    last_id: Optional[int] = None

    for line in output.splitlines():
        m = row_re.match(line)
        if m:
            vid = int(m.group(1))
            ports = [p.strip() for p in m.group(4).split(",") if p.strip()]
            vlans[vid] = VlanInfo(
                vlan_id=vid, name=m.group(2), status=m.group(3), ports=ports
            )
            last_id = vid
        elif last_id is not None and cont_re.match(line):
            vlans[last_id].ports.extend(
                p.strip() for p in line.strip().split(",") if p.strip()
            )
    return vlans


def parse_interfaces_trunk(output: str) -> List[TrunkPort]:
    trunks: Dict[str, TrunkPort] = {}
    section = None

    for line in output.splitlines():
        if re.search(r"Port\s+Mode\s+Encapsulation\s+Status", line):
            section = "header"
            continue
        elif re.search(r"Vlans allowed on trunk", line):
            section = "allowed"
            continue
        elif re.search(r"Vlans allowed and active", line):
            section = "active"
            continue
        elif re.search(r"Vlans in spanning tree", line):
            section = "stp"
            continue

        parts = line.split()
        if not parts or parts[0].startswith("-"):
            continue

        intf = parts[0]
        if section == "header" and len(parts) >= 5:
            try:
                native = int(parts[4])
                trunks.setdefault(intf, TrunkPort(interface=intf, native_vlan=1))
                trunks[intf].native_vlan = native
            except ValueError:
                pass
        elif section == "allowed" and len(parts) >= 2:
            trunks.setdefault(intf, TrunkPort(interface=intf, native_vlan=1))
            trunks[intf].allowed_vlans = expand_vlan_range(parts[1])
        elif section == "active" and len(parts) >= 2 and intf in trunks:
            trunks[intf].active_vlans = expand_vlan_range(parts[1])

    return list(trunks.values())


def audit(
    host: str,
    username: str,
    password: Optional[str],
    key_path: Optional[str],
    port: int,
) -> dict:
    client = ssh_connect(host, username, password, key_path, port)
    try:
        log.info("Connected to %s", host)
        vlan_out = run_command(client, "show vlan brief")
        trunk_out = run_command(client, "show interfaces trunk")
    finally:
        client.close()

    vlans = parse_vlan_brief(vlan_out)
    trunks = parse_interfaces_trunk(trunk_out)
    defined_ids = set(vlans)

    orphaned = [
        {"id": v.vlan_id, "name": v.name}
        for v in sorted(vlans.values(), key=lambda x: x.vlan_id)
        if not v.ports and v.status == "active" and v.vlan_id != 1
    ]

    trunk_anomalies = []
    for t in trunks:
        undefined = sorted(set(t.active_vlans) - defined_ids)
        if undefined:
            trunk_anomalies.append({"interface": t.interface, "undefined_vlans": undefined})

    return {
        "host": host,
        "vlan_count": len(vlans),
        "trunk_count": len(trunks),
        "vlans": [
            {
                "id": v.vlan_id,
                "name": v.name,
                "status": v.status,
                "port_count": len(v.ports),
            }
            for v in sorted(vlans.values(), key=lambda x: x.vlan_id)
        ],
        "trunks": [
            {
                "interface": t.interface,
                "native_vlan": t.native_vlan,
                "allowed": len(t.allowed_vlans),
                "active": len(t.active_vlans),
            }
            for t in trunks
        ],
        "orphaned_vlans": orphaned,
        "trunk_anomalies": trunk_anomalies,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit VLAN health on a Cisco IOS/IOS-XE switch via SSH."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", metavar="PATH", help="SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--orphans", action="store_true", help="Print only orphaned VLAN summary"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    password = args.password
    if not password and not args.key:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        result = audit(args.host, args.username, password, args.key, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"\nVLAN Audit — {result['host']}")
    print(f"  VLANs defined : {result['vlan_count']}")
    print(f"  Trunk ports   : {result['trunk_count']}")

    if not args.orphans:
        print("\n  VLANs:")
        for v in result["vlans"]:
            print(
                f"    {v['id']:>4}  {v['name']:<20}  {v['status']:<12}  "
                f"ports: {v['port_count']}"
            )

        if result["trunks"]:
            print("\n  Trunk Ports:")
            for t in result["trunks"]:
                print(
                    f"    {t['interface']:<22} native: {t['native_vlan']:<5} "
                    f"allowed: {t['allowed']:<5} active: {t['active']}"
                )

    orphaned = result["orphaned_vlans"]
    if orphaned:
        print(f"\n  Orphaned VLANs ({len(orphaned)} — active but no access ports):")
        for v in orphaned:
            print(f"    {v['id']:>4}  {v['name']}")
    else:
        print("\n  No orphaned VLANs detected.")

    anomalies = result["trunk_anomalies"]
    if anomalies:
        print(f"\n  Trunk Anomalies ({len(anomalies)} — active VLANs not in local DB):")
        for a in anomalies:
            print(f"    {a['interface']}: VLANs {a['undefined_vlans']}")


if __name__ == "__main__":
    main()
```