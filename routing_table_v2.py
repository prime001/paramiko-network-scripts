```python
"""
vrf_routing_table.py - Multi-VRF Routing Table Collector

Connects to a Cisco IOS/IOS-XE device via SSH and retrieves the IP routing
table for one or more VRFs, outputting structured data as a human-readable
table, JSON, or CSV.

Usage:
    python vrf_routing_table.py -H 192.168.1.1 -u admin -p secret
    python vrf_routing_table.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa \
        --vrf MGMT --vrf PROD --format json -o routes.json
    python vrf_routing_table.py -H 192.168.1.1 -u admin -p secret --all-vrfs

Prerequisites:
    pip install paramiko
    SSH must be enabled on the device; user needs at minimum privilege level 1.
    Tested against IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys

import paramiko

LOG = logging.getLogger(__name__)


def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        LOG.debug("stderr for %r: %s", command, err)
    return output


def parse_routing_table(raw: str, vrf: str = "default") -> list[dict]:
    routes = []
    last_prefix = None
    last_code = None

    for line in raw.splitlines():
        # Primary route line: protocol code + prefix + "is directly connected" or "[AD/metric] via"
        m = re.match(
            r"^([A-Z][A-Z* ]{0,5})\s+([\d.]+/\d+)\s+"
            r"(?:is directly connected,\s*(\S+)"
            r"|\[\d+/\d+\]\s+via\s+([\d.]+)(?:,\s*\S+)?,\s*(\S+))",
            line,
        )
        if m:
            code, prefix, iface_dc, nexthop, iface = m.groups()
            last_prefix = prefix
            last_code = code.strip()
            routes.append({
                "vrf": vrf,
                "code": last_code,
                "prefix": prefix,
                "nexthop": nexthop or "directly connected",
                "interface": iface_dc or iface or "",
            })
            continue

        # ECMP continuation line (indented with "[AD/metric] via ...")
        if last_prefix:
            m2 = re.match(
                r"^\s+\[\d+/\d+\]\s+via\s+([\d.]+)(?:,\s*\S+)?,\s*(\S+)",
                line,
            )
            if m2:
                nexthop2, iface2 = m2.groups()
                routes.append({
                    "vrf": vrf,
                    "code": last_code or "",
                    "prefix": last_prefix,
                    "nexthop": nexthop2,
                    "interface": iface2 or "",
                })

    return routes


def discover_vrfs(client: paramiko.SSHClient) -> list[str]:
    raw = ssh_exec(client, "show vrf brief")
    vrfs = []
    for line in raw.splitlines():
        m = re.match(r"^\s+(\S+)\s+\d+", line)
        if m and m.group(1).upper() not in ("NAME", "VRF"):
            vrfs.append(m.group(1))
    return vrfs


def collect_routes(client: paramiko.SSHClient, vrfs: list[str]) -> list[dict]:
    all_routes = []
    for vrf in vrfs:
        cmd = "show ip route" if vrf.lower() == "default" else f"show ip route vrf {vrf}"
        LOG.info("Running: %s", cmd)
        raw = ssh_exec(client, cmd)
        routes = parse_routing_table(raw, vrf=vrf)
        LOG.info("VRF %s: %d routes parsed", vrf, len(routes))
        all_routes.extend(routes)
    return all_routes


def write_table(routes: list[dict], dest) -> None:
    if not routes:
        dest.write("No routes found.\n")
        return
    dest.write(f"{'VRF':<18} {'Code':<6} {'Prefix':<20} {'Next-Hop':<18} Interface\n")
    dest.write("-" * 76 + "\n")
    for r in routes:
        dest.write(
            f"{r['vrf']:<18} {r['code']:<6} {r['prefix']:<20} "
            f"{r['nexthop']:<18} {r['interface']}\n"
        )


def write_json(routes: list[dict], dest) -> None:
    dest.write(json.dumps(routes, indent=2))
    dest.write("\n")


def write_csv(routes: list[dict], dest) -> None:
    fields = ["vrf", "code", "prefix", "nexthop", "interface"]
    writer = csv.DictWriter(dest, fieldnames=fields)
    writer.writeheader()
    writer.writerows(routes)


WRITERS = {"table": write_table, "json": write_json, "csv": write_csv}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect multi-VRF IP routing tables from Cisco IOS/IOS-XE devices."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", default=None)
    p.add_argument("--key", metavar="PATH", help="SSH private key file")
    p.add_argument("--port", type=int, default=22)
    p.add_argument(
        "--vrf",
        action="append",
        dest="vrfs",
        default=[],
        metavar="NAME",
        help="VRF to query (repeatable); defaults to global table only",
    )
    p.add_argument(
        "--all-vrfs",
        action="store_true",
        help="Auto-discover all VRFs via 'show vrf brief' and query each",
    )
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("-o", "--output", metavar="FILE", help="Output file (default: stdout)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    if not args.password and not args.key:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            key_filename=args.key,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        LOG.info("Connected to %s", args.host)

        vrfs = list(args.vrfs) or ["default"]
        if args.all_vrfs:
            discovered = discover_vrfs(client)
            seen = set(vrfs)
            vrfs.extend(v for v in discovered if v not in seen)
            LOG.info("Querying VRFs: %s", vrfs)

        routes = collect_routes(client, vrfs)

    except paramiko.AuthenticationException:
        print(f"ERROR: authentication failed for {args.username}@{args.host}", file=sys.stderr)
        return 1
    except paramiko.SSHException as exc:
        print(f"ERROR: SSH error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()

    writer = WRITERS[args.format]
    if args.output:
        open_kwargs = {"newline": ""} if args.format == "csv" else {}
        with open(args.output, "w", **open_kwargs) as fh:
            writer(routes, fh)
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        writer(routes, sys.stdout)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```