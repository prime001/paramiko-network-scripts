Writing a VLAN audit script since `credential_vault.py` and `credential_vault_v2.py` already cover credential vault functionality — this fills a clear gap in the portfolio.

```python
"""
vlan_audit.py — VLAN Audit Tool for Cisco IOS Switches

Connects to a Cisco switch via SSH (paramiko), retrieves VLAN and trunk
information, then produces an audit report identifying active VLANs, port
assignments, trunk pruning, and empty VLANs that may be cleanup candidates.

Usage:
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret
    python vlan_audit.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa --json
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret --min-ports 0

Prerequisites:
    pip install paramiko
    SSH access to target device with 'show' privilege.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr for %r: %s", command, err)
    return output


def parse_vlan_brief(output: str) -> dict:
    """Return {vlan_id: {"name": str, "status": str, "ports": [str]}}."""
    vlans = {}
    current_id = None

    for line in output.splitlines():
        # Primary VLAN line: id  name  status  ports...
        m = re.match(r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|suspended)\s*(.*)", line)
        if m:
            vid, name, status, ports_raw = m.groups()
            current_id = int(vid)
            ports = [p.strip() for p in ports_raw.split(",") if p.strip()]
            vlans[current_id] = {"name": name, "status": status, "ports": ports}
        elif current_id and re.match(r"^\s{20,}", line):
            # Continuation line with more ports
            extra = [p.strip() for p in line.split(",") if p.strip()]
            vlans[current_id]["ports"].extend(extra)

    return vlans


def parse_trunk_vlans(output: str) -> dict:
    """Return {port: {"native": str, "allowed": str, "active": str}}."""
    trunks = {}
    section = None
    port_order = []

    for line in output.splitlines():
        line = line.rstrip()
        if re.match(r"^Port\s+Native vlan", line):
            section = "native"
            continue
        if re.match(r"^Port\s+Vlans allowed on trunk", line):
            section = "allowed"
            continue
        if re.match(r"^Port\s+Vlans allowed and active", line):
            section = "active"
            continue
        if re.match(r"^Port\s+Vlans in spanning", line):
            section = None
            continue

        m = re.match(r"^(\S+)\s+(.+)", line)
        if m and section:
            port, value = m.group(1), m.group(2).strip()
            if port not in trunks:
                trunks[port] = {}
                port_order.append(port)
            trunks[port][section] = value

    return trunks


def expand_vlan_range(vlan_str: str) -> set:
    """Expand '1-5,10,20-22' into {1,2,3,4,5,10,20,21,22}."""
    result = set()
    for part in vlan_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                result.update(range(int(lo), int(hi) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            result.add(int(part))
    return result


def audit(host: str, port: int, username: str, password: str,
          key_path: str, min_ports: int) -> dict:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = dict(hostname=host, port=port, username=username, timeout=10)
    if key_path:
        connect_kwargs["key_filename"] = key_path
    else:
        connect_kwargs["password"] = password

    log.info("Connecting to %s:%d as %s", host, port, username)
    try:
        client.connect(**connect_kwargs)
    except paramiko.AuthenticationException:
        log.error("Authentication failed")
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    log.info("Fetching VLAN database")
    vlan_output = ssh_exec(client, "show vlan brief")
    log.info("Fetching trunk information")
    trunk_output = ssh_exec(client, "show interfaces trunk")
    client.close()

    vlans = parse_vlan_brief(vlan_output)
    trunks = parse_trunk_vlans(trunk_output)

    # VLANs active on at least one trunk
    trunk_active_vlans: set = set()
    for info in trunks.values():
        trunk_active_vlans.update(expand_vlan_range(info.get("active", "")))

    results = {
        "host": host,
        "vlan_count": len(vlans),
        "trunk_count": len(trunks),
        "vlans": [],
        "trunks": [],
        "empty_vlans": [],
        "summary": {},
    }

    for vid, info in sorted(vlans.items()):
        port_count = len(info["ports"])
        on_trunk = vid in trunk_active_vlans
        entry = {
            "id": vid,
            "name": info["name"],
            "status": info["status"],
            "access_ports": info["ports"],
            "port_count": port_count,
            "on_active_trunk": on_trunk,
        }
        results["vlans"].append(entry)
        if port_count < min_ports and not on_trunk and vid not in (1,):
            results["empty_vlans"].append(vid)

    for port, info in sorted(trunks.items()):
        results["trunks"].append({
            "port": port,
            "native_vlan": info.get("native", ""),
            "allowed": info.get("allowed", ""),
            "active": info.get("active", ""),
        })

    results["summary"] = {
        "active_vlans": sum(1 for v in results["vlans"] if v["status"] == "active"),
        "vlans_with_ports": sum(1 for v in results["vlans"] if v["port_count"] > 0),
        "vlans_on_trunks": len(trunk_active_vlans & set(vlans)),
        "candidate_cleanup_vlans": len(results["empty_vlans"]),
    }

    return results


def print_report(data: dict) -> None:
    print(f"\n{'='*60}")
    print(f"VLAN Audit Report — {data['host']}")
    print(f"{'='*60}")
    s = data["summary"]
    print(f"  Total VLANs        : {data['vlan_count']}")
    print(f"  Active VLANs       : {s['active_vlans']}")
    print(f"  VLANs with ports   : {s['vlans_with_ports']}")
    print(f"  VLANs on trunks    : {s['vlans_on_trunks']}")
    print(f"  Trunk interfaces   : {data['trunk_count']}")
    print(f"  Cleanup candidates : {s['candidate_cleanup_vlans']}")

    print(f"\n{'─'*60}")
    print(f"{'ID':<6} {'Name':<20} {'Status':<12} {'Ports':<5} {'Trunk'}")
    print(f"{'─'*60}")
    for v in data["vlans"]:
        trunk_flag = "yes" if v["on_active_trunk"] else ""
        print(f"{v['id']:<6} {v['name']:<20} {v['status']:<12} "
              f"{v['port_count']:<5} {trunk_flag}")

    if data["empty_vlans"]:
        print(f"\nCleanup candidates (no ports, not on trunk): "
              f"{', '.join(str(v) for v in data['empty_vlans'])}")

    if data["trunks"]:
        print(f"\nTrunk Interfaces:")
        for t in data["trunks"]:
            print(f"  {t['port']:15s}  native={t['native_vlan']}  "
                  f"active={t['active'][:40]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Audit VLANs on a Cisco IOS switch via SSH"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_path", default=None,
                        help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument("--min-ports", type=int, default=1,
                        help="Port count below which a VLAN is a cleanup candidate")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON instead of formatted report")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if not args.key_path and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    data = audit(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        key_path=args.key_path,
        min_ports=args.min_ports,
    )

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print_report(data)


if __name__ == "__main__":
    main()
```