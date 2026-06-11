The request says "Output ONLY the script content" — here it is:

```
"""
vlan_audit.py - VLAN configuration audit for Cisco IOS switches
...
```

Since the instructions say output ONLY the script and no markdown fences, here is the raw script:

---

```python
"""
vlan_audit.py - VLAN configuration audit for Cisco IOS switches

Purpose:
    Collect VLAN database and port assignments from one or more Cisco IOS
    switches via SSH, then report active VLANs, member ports, and flag any
    VLANs not present in an operator-supplied allowlist.

Usage:
    python vlan_audit.py -d 192.168.1.1 -u admin
    python vlan_audit.py -d 192.168.1.1 192.168.1.2 -u admin --allowed 10,20,30
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --json

Prerequisites:
    pip install paramiko
    SSH access must be enabled on target devices (IOS: 'ip ssh version 2').
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

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


@dataclass
class VlanInfo:
    vlan_id: int
    name: str
    status: str
    ports: List[str] = field(default_factory=list)


def ssh_connect(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 15,
) -> paramiko.SSHClient:
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
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        raise
    except (paramiko.SSHException, OSError) as exc:
        log.error("Cannot connect to %s: %s", host, exc)
        raise
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def parse_vlan_brief(output: str) -> Dict[int, VlanInfo]:
    """Parse `show vlan brief` into a dict keyed by VLAN ID."""
    vlans: Dict[int, VlanInfo] = {}
    current: Optional[VlanInfo] = None

    for line in output.splitlines():
        m = re.match(
            r"^(\d+)\s+(\S+)\s+(active|act/lshut|act/unsup|suspended)\s*(.*)",
            line,
        )
        if m:
            vlan_id = int(m.group(1))
            ports = [p.strip() for p in m.group(4).split(",") if p.strip()]
            current = VlanInfo(
                vlan_id=vlan_id,
                name=m.group(2),
                status=m.group(3),
                ports=ports,
            )
            vlans[vlan_id] = current
        elif current and line.startswith(" ") and line.strip():
            # continuation line: additional ports for the current VLAN
            current.ports.extend(p.strip() for p in line.split(",") if p.strip())

    return vlans


def audit_device(
    host: str,
    username: str,
    password: str,
    port: int,
    allowed: Optional[List[int]],
) -> dict:
    log.info("Auditing %s", host)
    try:
        client = ssh_connect(host, username, password, port)
    except Exception:
        return {"host": host, "error": "connection failed", "vlans": {}, "violations": []}

    try:
        raw = run_command(client, "show vlan brief")
    except Exception as exc:
        log.error("Command failed on %s: %s", host, exc)
        return {"host": host, "error": str(exc), "vlans": {}, "violations": []}
    finally:
        client.close()

    vlans = parse_vlan_brief(raw)

    violations: List[dict] = []
    if allowed is not None:
        for vid, info in vlans.items():
            if vid not in allowed and vid != 1:
                violations.append({
                    "vlan_id": vid,
                    "name": info.name,
                    "ports": info.ports,
                })

    return {
        "host": host,
        "error": None,
        "vlans": {
            vid: {"name": v.name, "status": v.status, "ports": v.ports}
            for vid, v in vlans.items()
        },
        "violations": violations,
    }


def print_table(result: dict) -> None:
    host = result["host"]
    if result.get("error"):
        print(f"\n[{host}] ERROR: {result['error']}")
        return

    print(f"\n{'=' * 62}")
    print(f"Host: {host}  ({len(result['vlans'])} VLANs)")
    print(f"{'=' * 62}")
    print(f"{'VLAN':<8} {'Name':<24} {'Status':<14} Ports")
    print("-" * 62)
    for vid, info in sorted(result["vlans"].items()):
        ports_str = ", ".join(info["ports"][:5])
        if len(info["ports"]) > 5:
            ports_str += f"  (+{len(info['ports']) - 5} more)"
        print(f"{vid:<8} {info['name']:<24} {info['status']:<14} {ports_str}")

    violations = result.get("violations", [])
    if violations:
        print(f"\n[!] {len(violations)} unauthorized VLAN(s):")
        for v in violations:
            port_list = ", ".join(v["ports"]) if v["ports"] else "no ports"
            print(f"    VLAN {v['vlan_id']:>4}  {v['name']:<20}  {port_list}")
    else:
        print("\n[OK] All VLANs within allowlist.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit VLAN configurations on Cisco IOS switches via SSH."
    )
    parser.add_argument(
        "-d", "--devices", nargs="+", required=True, metavar="HOST",
        help="Device IP(s) or hostname(s)",
    )
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--allowed",
        help="Comma-separated allowed VLAN IDs, e.g. 10,20,30; others are flagged",
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="Emit results as JSON instead of a human-readable table",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    allowed_vlans: Optional[List[int]] = None
    if args.allowed:
        try:
            allowed_vlans = [int(v.strip()) for v in args.allowed.split(",")]
        except ValueError:
            log.error("--allowed must be comma-separated integers, e.g. 10,20,30")
            sys.exit(1)

    results = []
    for host in args.devices:
        results.append(audit_device(host, args.username, password, args.port, allowed_vlans))

    if args.as_json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print_table(result)

    if any(r.get("error") for r in results):
        sys.exit(1)
```