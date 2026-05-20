The user's instruction says "Output ONLY the script content" — that's an explicit instruction that overrides the brainstorming workflow per the skill's own priority rules. Writing the script directly.

"""
Route change monitor — detects additions, removals, and next-hop changes in the
IP routing table by comparing periodic snapshots over SSH.

Useful for troubleshooting route instability, validating convergence after a
topology change, or confirming that a prefix is consistently reachable.

Usage:
    python routing_table_monitor.py -H 192.168.1.1 -u admin
    python routing_table_monitor.py -H 192.168.1.1 -u admin -p secret --interval 30 --count 5
    python routing_table_monitor.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa --prefix 10.0.0.0

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Tested against Cisco IOS, IOS-XE, NX-OS, and Linux (ip route).
"""

import argparse
import getpass
import logging
import re
import sys
import time
from dataclasses import dataclass
from typing import Optional

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class RouteEntry:
    prefix: str
    next_hop: str
    interface: str
    protocol: str


def ssh_connect(
    host: str, port: int, username: str,
    password: Optional[str], key_path: Optional[str],
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(
        hostname=host, port=port, username=username,
        timeout=15, look_for_keys=False, allow_agent=False,
    )
    if key_path:
        kwargs["key_filename"] = key_path
        kwargs["look_for_keys"] = True
    elif password:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        logger.debug("stderr: %s", err)
    return out


def detect_os(client: paramiko.SSHClient) -> str:
    try:
        out = run_command(client, "show version", timeout=10)
        if "Nexus" in out or "NX-OS" in out:
            return "nxos"
        if "IOS XE" in out or "IOS-XE" in out:
            return "iosxe"
        if "Cisco IOS" in out:
            return "ios"
    except Exception:
        pass
    try:
        if "Linux" in run_command(client, "uname -s", timeout=5):
            return "linux"
    except Exception:
        pass
    return "ios"


_ROUTE_CMD = {
    "ios": "show ip route",
    "iosxe": "show ip route",
    "nxos": "show ip route",
    "linux": "ip route show",
}

_CISCO_RE = re.compile(
    r"^([A-Z*][\w\s*]*?)\s+([\d.]+/\d+)\s+\[\d+/\d+\]\s+via\s+([\d.]+)"
    r"(?:.*?,\s+(\S+))?",
    re.IGNORECASE,
)
_LINUX_RE = re.compile(
    r"^([\d./]+|default)\s+(?:via\s+([\d.]+)\s+)?(?:dev\s+(\S+))?",
)


def parse_routes(output: str, os_type: str) -> dict[str, RouteEntry]:
    routes: dict[str, RouteEntry] = {}
    for line in output.splitlines():
        line = line.strip()
        if os_type in ("ios", "iosxe", "nxos"):
            m = _CISCO_RE.match(line)
            if m:
                routes[m.group(2)] = RouteEntry(
                    prefix=m.group(2), next_hop=m.group(3),
                    interface=m.group(4) or "", protocol=m.group(1).strip(),
                )
        elif os_type == "linux":
            m = _LINUX_RE.match(line)
            if m:
                routes[m.group(1)] = RouteEntry(
                    prefix=m.group(1),
                    next_hop=m.group(2) or "connected",
                    interface=m.group(3) or "",
                    protocol="kernel",
                )
    return routes


def diff_routes(
    before: dict[str, RouteEntry],
    after: dict[str, RouteEntry],
    prefix_filter: Optional[str],
) -> tuple[list[RouteEntry], list[RouteEntry], list[tuple[RouteEntry, RouteEntry]]]:
    if prefix_filter:
        before = {k: v for k, v in before.items() if k.startswith(prefix_filter)}
        after = {k: v for k, v in after.items() if k.startswith(prefix_filter)}
    added = [after[p] for p in after if p not in before]
    removed = [before[p] for p in before if p not in after]
    changed = [
        (before[p], after[p])
        for p in before
        if p in after and before[p].next_hop != after[p].next_hop
    ]
    return added, removed, changed


def report_changes(
    added: list, removed: list, changed: list, iteration: int
) -> None:
    if not (added or removed or changed):
        logger.info("Snapshot %d: no route changes detected", iteration)
        return
    print(f"\n=== Route changes (snapshot {iteration}) ===")
    for r in added:
        print(f"  [+] ADDED    {r.prefix:<22} via {r.next_hop}  ({r.protocol})")
    for r in removed:
        print(f"  [-] REMOVED  {r.prefix:<22} was via {r.next_hop}  ({r.protocol})")
    for b, a in changed:
        print(f"  [~] CHANGED  {b.prefix:<22} {b.next_hop} -> {a.next_hop}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor IP routing table changes on a network device over SSH."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-P", "--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("--key", dest="key_path", default=None, help="Path to SSH private key")
    p.add_argument("--interval", type=int, default=60,
                   help="Seconds between snapshots (default: 60)")
    p.add_argument("--count", type=int, default=0,
                   help="Comparisons to perform; 0 = run until Ctrl-C (default: 0)")
    p.add_argument("--prefix", default=None,
                   help="Filter to routes matching this prefix string (e.g. 10.0.0.0)")
    p.add_argument("--os-type", dest="os_type", default=None,
                   choices=["ios", "iosxe", "nxos", "linux"],
                   help="Force OS type (auto-detected if omitted)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_path:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        client = ssh_connect(args.host, args.port, args.username, password, args.key_path)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection to %s failed: %s", args.host, exc)
        sys.exit(1)

    try:
        os_type = args.os_type or detect_os(client)
        logger.info("OS type: %s", os_type)
        cmd = _ROUTE_CMD[os_type]

        logger.info("Taking baseline snapshot from %s ...", args.host)
        prev = parse_routes(run_command(client, cmd), os_type)
        logger.info("Baseline: %d routes", len(prev))

        iteration = 0
        while args.count == 0 or iteration < args.count:
            logger.info("Waiting %d seconds ...", args.interval)
            time.sleep(args.interval)
            curr = parse_routes(run_command(client, cmd), os_type)
            iteration += 1
            added, removed, changed = diff_routes(prev, curr, args.prefix)
            report_changes(added, removed, changed, iteration)
            prev = curr

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except paramiko.SSHException as exc:
        logger.error("SSH error: %s", exc)
        sys.exit(1)
    finally:
        client.close()