The user's explicit instruction is to output only the script content — that overrides the brainstorming workflow. Writing the routing-table monitor script now.

```python
"""
routing_table_monitor.py — Route Change Monitor via SSH

Connects to a network device over SSH, captures the IP routing table,
and detects route additions and withdrawals across polling intervals.
Useful for validating convergence after topology changes or verifying
that route redistribution is behaving as expected.

Prerequisites:
    pip install paramiko

Usage:
    # Single snapshot
    python routing_table_monitor.py --host 192.168.1.1 --user admin --password secret

    # Watch for changes every 30 seconds, log to file
    python routing_table_monitor.py --host 192.168.1.1 --user admin --password secret \
        --watch --interval 30 --log route_changes.log

    # Key-based auth
    python routing_table_monitor.py --host 192.168.1.1 --user admin --key ~/.ssh/id_rsa \
        --watch --interval 60
"""

import argparse
import logging
import re
import sys
import time
from datetime import datetime

import paramiko


def setup_logging(log_file: str | None) -> logging.Logger:
    logger = logging.getLogger("route_monitor")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def ssh_connect(host: str, port: int, user: str, password: str | None,
                key_path: str | None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {"hostname": host, "port": port, "username": user,
                      "timeout": 15, "look_for_keys": False}
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def fetch_routing_table(client: paramiko.SSHClient) -> str:
    _, stdout, stderr = client.exec_command("show ip route", timeout=30)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        raise RuntimeError(f"Device returned error: {err}")
    return output


def parse_routes(output: str) -> dict[str, str]:
    """Return {prefix: full_route_line} from 'show ip route' output."""
    routes = {}
    # Matches IOS-style lines: C/S/O/B/R... prefix/len [ad/metric] via next-hop
    pattern = re.compile(
        r"^\s*([A-Z*]{1,2})\s+([\d.]+(?:/\d+)?)\s+.*$", re.MULTILINE
    )
    for match in pattern.finditer(output):
        prefix = match.group(2)
        routes[prefix] = match.group(0).strip()
    return routes


def diff_routes(before: dict[str, str], after: dict[str, str]
                ) -> tuple[dict, dict, dict]:
    added = {p: r for p, r in after.items() if p not in before}
    removed = {p: r for p, r in before.items() if p not in after}
    changed = {
        p: (before[p], after[p])
        for p in after
        if p in before and before[p] != after[p]
    }
    return added, removed, changed


def report_snapshot(routes: dict[str, str], logger: logging.Logger) -> None:
    logger.info(f"Routing table snapshot: {len(routes)} routes")
    for prefix, line in sorted(routes.items()):
        logger.info(f"  {line}")


def report_diff(added: dict, removed: dict, changed: dict,
                logger: logging.Logger) -> None:
    if not (added or removed or changed):
        logger.info("No route changes detected")
        return
    for prefix, line in sorted(added.items()):
        logger.info(f"[ADDED]   {prefix}  ->  {line}")
    for prefix, line in sorted(removed.items()):
        logger.info(f"[REMOVED] {prefix}  ->  {line}")
    for prefix, (old, new) in sorted(changed.items()):
        logger.info(f"[CHANGED] {prefix}")
        logger.info(f"          was: {old}")
        logger.info(f"          now: {new}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor IP routing table changes on a network device"
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--user", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password")
    p.add_argument("--key", dest="key_path", help="Path to SSH private key")
    p.add_argument("--watch", action="store_true",
                   help="Poll continuously for changes")
    p.add_argument("--interval", type=int, default=60,
                   help="Polling interval in seconds (default: 60)")
    p.add_argument("--log", dest="log_file", help="Write output to this log file")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if not args.password and not args.key_path:
        print("ERROR: provide --password or --key", file=sys.stderr)
        sys.exit(1)

    logger = setup_logging(args.log_file)
    logger.info(f"Connecting to {args.host}:{args.port} as {args.user}")

    try:
        client = ssh_connect(args.host, args.port, args.user,
                             args.password, args.key_path)
    except Exception as exc:
        logger.error(f"SSH connection failed: {exc}")
        sys.exit(1)

    try:
        raw = fetch_routing_table(client)
        previous = parse_routes(raw)
        report_snapshot(previous, logger)

        if not args.watch:
            client.close()
            sys.exit(0)

        logger.info(f"Watching for changes every {args.interval}s (Ctrl-C to stop)")
        while True:
            time.sleep(args.interval)
            try:
                raw = fetch_routing_table(client)
            except Exception:
                logger.warning("Lost connection, reconnecting...")
                try:
                    client.close()
                except Exception:
                    pass
                client = ssh_connect(args.host, args.port, args.user,
                                     args.password, args.key_path)
                raw = fetch_routing_table(client)

            current = parse_routes(raw)
            added, removed, changed = diff_routes(previous, current)
            report_diff(added, removed, changed, logger)
            previous = current

    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
    except Exception as exc:
        logger.error(f"Error: {exc}")
        sys.exit(1)
    finally:
        client.close()
```