routing_table_v3.py - VRF-aware per-prefix route lookup and next-hop analysis.

Purpose:
    Query specific IP prefixes on one or more Cisco IOS/IOS-XE devices and
    report matching routing-table entries (protocol, admin distance, metric,
    next-hop, egress interface, age).  Unlike a full-table dump, this tool
    is designed for targeted verification after a change or for auditing
    route propagation across a fleet.

Usage:
    python routing_table_v3.py -d 192.168.1.1 -u admin -p secret \
        --prefixes 10.0.0.0/8 172.16.0.0/12

    # Multiple devices, specific VRF, JSON output
    python routing_table_v3.py -d 192.168.1.1,192.168.1.2 -u admin \
        --prefixes 10.10.0.0/24 --vrf MGMT --output json

Prerequisites:
    pip install paramiko
    SSH access with at least read-level privileges on target devices.
"""

import argparse
import getpass
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass
from typing import List, Optional

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# IOS "show ip route <prefix>" — dynamic (BGP/OSPF/EIGRP/RIP) entries
_DYN_RE = re.compile(
    r"^\s*(?P<proto>[A-Z][A-Z*\s]{0,3})\s+"
    r"(?P<prefix>\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+"
    r"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<nexthop>\S+)"
    r"(?:,\s*(?P<age>\S+))?(?:,\s*(?P<iface>\S+))?",
    re.MULTILINE,
)

# Connected / local entries
_CONN_RE = re.compile(
    r"^\s*(?P<proto>[CL])\s+"
    r"(?P<prefix>\d+\.\d+\.\d+\.\d+(?:/\d+)?)"
    r"(?:\s+is\s+directly\s+connected,\s*(?P<iface>\S+))?",
    re.MULTILINE,
)

# Static routes (S)
_STATIC_RE = re.compile(
    r"^\s*(?P<proto>S\*?)\s+"
    r"(?P<prefix>\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+"
    r"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<nexthop>\S+)"
    r"(?:,\s*(?P<iface>\S+))?",
    re.MULTILINE,
)


@dataclass
class RouteEntry:
    device: str
    vrf: Optional[str]
    queried_prefix: str
    matched_prefix: str
    protocol: str
    admin_distance: Optional[int]
    metric: Optional[int]
    nexthop: Optional[str]
    interface: Optional[str]
    age: Optional[str]


def _drain(channel, timeout: int = 10) -> str:
    buf = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            buf += channel.recv(65535).decode("utf-8", errors="replace")
            if re.search(r"[#>]\s*$", buf):
                break
        else:
            time.sleep(0.1)
    return buf


def _exec(client: paramiko.SSHClient, command: str, timeout: int) -> str:
    shell = client.invoke_shell()
    _drain(shell, timeout=5)
    shell.send("terminal length 0\n")
    _drain(shell, timeout=3)
    shell.send(command + "\n")
    output = _drain(shell, timeout=timeout)
    shell.close()
    return output


def _parse(raw: str, device: str, vrf: Optional[str], queried: str) -> List[RouteEntry]:
    entries: List[RouteEntry] = []

    for pat in (_DYN_RE, _STATIC_RE):
        for m in pat.finditer(raw):
            entries.append(RouteEntry(
                device=device, vrf=vrf, queried_prefix=queried,
                matched_prefix=m.group("prefix"),
                protocol=m.group("proto").strip(),
                admin_distance=int(m.group("ad")),
                metric=int(m.group("metric")),
                nexthop=m.group("nexthop"),
                interface=m.group("iface"),
                age=m.group("age") if "age" in m.groupdict() else None,
            ))

    for m in _CONN_RE.finditer(raw):
        entries.append(RouteEntry(
            device=device, vrf=vrf, queried_prefix=queried,
            matched_prefix=m.group("prefix"),
            protocol=m.group("proto").strip(),
            admin_distance=None, metric=None, nexthop=None,
            interface=m.group("iface"), age=None,
        ))

    if not entries:
        logger.warning("%s: prefix %s not found (vrf=%s)", device, queried, vrf or "global")
    return entries


def lookup(
    host: str, username: str, password: str,
    prefix: str, vrf: Optional[str],
    port: int, timeout: int,
) -> List[RouteEntry]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
        )
    except paramiko.AuthenticationException:
        logger.error("%s: authentication failed", host)
        return []
    except Exception as exc:
        logger.error("%s: connection error — %s", host, exc)
        return []

    try:
        cmd = (
            f"show ip route vrf {vrf} {prefix}" if vrf
            else f"show ip route {prefix}"
        )
        raw = _exec(client, cmd, timeout)
        return _parse(raw, host, vrf, prefix)
    finally:
        client.close()


def _print_table(entries: List[RouteEntry]) -> None:
    if not entries:
        print("No routes found.")
        return
    hdr = f"{'DEVICE':<18} {'VRF':<10} {'QUERIED':<20} {'MATCHED':<20} {'PROTO':<6} {'AD/MET':<10} {'NEXTHOP':<18} {'IFACE':<20} {'AGE'}"
    print(hdr)
    print("-" * len(hdr))
    for e in entries:
        ad_met = f"{e.admin_distance}/{e.metric}" if e.admin_distance is not None else "direct"
        print(
            f"{e.device:<18} {e.vrf or 'global':<10} {e.queried_prefix:<20} "
            f"{e.matched_prefix:<20} {e.protocol:<6} {ad_met:<10} "
            f"{e.nexthop or 'connected':<18} {e.interface or '':<20} {e.age or ''}"
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Look up specific prefixes in the routing table of Cisco IOS devices."
    )
    ap.add_argument("-d", "--devices", required=True,
                    help="Comma-separated device IPs or hostnames")
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password", default=None,
                    help="SSH password (prompted if omitted)")
    ap.add_argument("--prefixes", nargs="+", required=True,
                    help="Prefixes to look up, e.g. 10.0.0.0/8 192.168.1.1")
    ap.add_argument("--vrf", default=None, help="VRF name (default: global routing table)")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--output", choices=["table", "json"], default="table")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")
    devices = [d.strip() for d in args.devices.split(",") if d.strip()]

    all_entries: List[RouteEntry] = []
    for device in devices:
        for prefix in args.prefixes:
            logger.info("Querying %s — prefix %s (vrf=%s)", device, prefix, args.vrf or "global")
            all_entries.extend(lookup(
                host=device, username=args.username, password=password,
                prefix=prefix, vrf=args.vrf, port=args.port, timeout=args.timeout,
            ))

    if args.output == "json":
        print(json.dumps([asdict(e) for e in all_entries], indent=2))
    else:
        _print_table(all_entries)

    return 0 if all_entries else 1


if __name__ == "__main__":
    sys.exit(main())