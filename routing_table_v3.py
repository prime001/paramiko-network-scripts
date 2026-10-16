routing_table_monitor.py - Routing Table Change Monitor

Polls a network device's routing table at a configurable interval and reports
added or removed routes in real time. Useful for detecting route flaps,
unauthorized changes, or convergence issues after topology changes.

Usage:
    python routing_table_monitor.py -d 192.168.1.1 -u admin -p secret
    python routing_table_monitor.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa \
        --interval 30 --count 10 --prefix 10.0.0.0/8

Prerequisites:
    pip install paramiko
    Device must accept SSH and respond to 'show ip route' (Cisco IOS/IOS-XE)
    or 'show route' (Junos -- use --junos flag).
"""

import argparse
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 30) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def connect(host: str, port: int, username: str, password: str | None,
            key_path: str | None, timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(hostname=host, port=port, username=username,
                          timeout=timeout, look_for_keys=False, allow_agent=False)
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def parse_ios_routes(output: str) -> set[str]:
    """Extract network prefixes from 'show ip route' output."""
    routes = set()
    pattern = re.compile(
        r"^\s*[A-Z*>?]\S*\s+([\d.]+/\d+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        routes.add(match.group(1))
    return routes


def parse_junos_routes(output: str) -> set[str]:
    """Extract network prefixes from 'show route' output (Junos)."""
    routes = set()
    pattern = re.compile(r"^([\d.]+/\d+)\s+", re.MULTILINE)
    for match in pattern.finditer(output):
        routes.add(match.group(1))
    return routes


def filter_routes(routes: set[str], prefix_filter: str | None) -> set[str]:
    if not prefix_filter:
        return routes
    net, length = prefix_filter.split("/")
    net_parts = [int(x) for x in net.split(".")]
    mask = int(length)

    def in_prefix(route: str) -> bool:
        addr = route.split("/")[0]
        addr_parts = [int(x) for x in addr.split(".")]
        for i in range(min(mask // 8, 4)):
            if addr_parts[i] != net_parts[i]:
                return False
        return True

    return {r for r in routes if in_prefix(r)}


def poll_once(client: paramiko.SSHClient, junos: bool, prefix_filter: str | None,
              disable_pager: bool) -> set[str]:
    if disable_pager:
        if junos:
            ssh_exec(client, "set cli screen-length 0")
        else:
            ssh_exec(client, "terminal length 0")
    command = "show route" if junos else "show ip route"
    output = ssh_exec(client, command)
    parser = parse_junos_routes if junos else parse_ios_routes
    routes = parser(output)
    return filter_routes(routes, prefix_filter)


def monitor(args: argparse.Namespace) -> int:
    password = args.password
    if not password and not args.key:
        import getpass
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        client = connect(args.device, args.port, args.username, password,
                         args.key, args.timeout)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        return 1

    log.info("Connected to %s", args.device)
    baseline: set[str] | None = None
    iteration = 0

    try:
        while args.count == 0 or iteration < args.count:
            try:
                current = poll_once(client, args.junos, args.prefix, not args.no_pager)
            except Exception as exc:
                log.warning("Poll failed: %s -- retrying next interval", exc)
                time.sleep(args.interval)
                iteration += 1
                continue

            if baseline is None:
                log.info("Baseline captured: %d routes", len(current))
                baseline = current
            else:
                added = current - baseline
                removed = baseline - current
                if added or removed:
                    log.warning(
                        "CHANGE DETECTED (+%d/-%d routes) | total: %d",
                        len(added), len(removed), len(current),
                    )
                    for r in sorted(added):
                        log.warning("  + %s", r)
                    for r in sorted(removed):
                        log.warning("  - %s", r)
                    if args.update_baseline:
                        baseline = current
                        log.info("Baseline updated to %d routes", len(baseline))
                else:
                    log.info("No change (%d routes stable)", len(current))

            iteration += 1
            if args.count == 0 or iteration < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("Interrupted.")
    finally:
        client.close()

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor routing table changes on a network device via SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", metavar="PATH", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds")
    parser.add_argument("--interval", type=int, default=60,
                        help="Poll interval in seconds (default: 60)")
    parser.add_argument("--count", type=int, default=0,
                        help="Number of polls (0 = run forever)")
    parser.add_argument("--prefix", metavar="NET/LEN",
                        help="Filter to routes within this prefix (e.g. 10.0.0.0/8)")
    parser.add_argument("--update-baseline", action="store_true",
                        help="Update baseline after each detected change")
    parser.add_argument("--junos", action="store_true",
                        help="Target is a Junos device (uses 'show route')")
    parser.add_argument("--no-pager", action="store_true",
                        help="Skip 'terminal length 0' pager disable command")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sys.exit(monitor(args))


if __name__ == "__main__":
    main()