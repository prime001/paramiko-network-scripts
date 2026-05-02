```python
"""cdp_lldp_neighbors.py - Collect CDP/LLDP neighbor tables from Cisco IOS devices.

Purpose:
    SSH into one or more Cisco IOS/IOS-XE devices and retrieve neighbor
    adjacency data via CDP and/or LLDP.  Useful for topology discovery,
    change validation, and audit trails.

Usage:
    python cdp_lldp_neighbors.py -H 192.168.1.1 -u admin -p secret
    python cdp_lldp_neighbors.py -H 192.168.1.1 -u admin --ask-pass --lldp
    python cdp_lldp_neighbors.py --hosts-file devices.txt -u admin -p secret --json
    python cdp_lldp_neighbors.py -H 10.0.0.1 -u admin -p secret --json -o topo.json

Prerequisites:
    pip install paramiko
    CDP or LLDP must be enabled on target devices.
    SSH access with at minimum privilege level 1 (show commands only).
"""

import argparse
import getpass
import json
import logging
import re
import sys
from typing import Any

import paramiko

LOG = logging.getLogger(__name__)


def _ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        LOG.debug("stderr for %r: %s", command, err)
    return out


def _connect(host: str, username: str, password: str,
             port: int = 22, timeout: int = 10) -> paramiko.SSHClient:
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


def _parse_cdp(raw: str) -> list[dict[str, str]]:
    neighbors: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in raw.splitlines():
        if line.startswith("---"):
            if current:
                neighbors.append(current)
            current = {}
            continue
        m = re.match(r"^Device ID:\s*(.+)", line)
        if m:
            current["device_id"] = m.group(1).strip()
        m = re.match(r"^\s+IP address:\s*(\S+)", line)
        if m and "ip_address" not in current:
            current["ip_address"] = m.group(1)
        m = re.match(r"^Platform:\s*(.+?),\s*Capabilities:\s*(.+)", line)
        if m:
            current["platform"] = m.group(1).strip()
            current["capabilities"] = m.group(2).strip()
        m = re.match(r"^Interface:\s*(\S+?),\s*Port ID.*?:\s*(\S+)", line)
        if m:
            current["local_interface"] = m.group(1)
            current["remote_interface"] = m.group(2)
    if current:
        neighbors.append(current)
    return [n for n in neighbors if "device_id" in n]


def _parse_lldp(raw: str) -> list[dict[str, str]]:
    neighbors: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in raw.splitlines():
        if re.match(r"^-{10,}", line):
            if current:
                neighbors.append(current)
            current = {}
            continue
        m = re.match(r"^Local Intf:\s*(\S+)", line)
        if m:
            current["local_interface"] = m.group(1)
        m = re.match(r"^System Name:\s*(.+)", line)
        if m:
            current["device_id"] = m.group(1).strip()
        m = re.match(r"^\s+IP:\s*(\S+)", line)
        if m and "ip_address" not in current:
            current["ip_address"] = m.group(1)
        m = re.match(r"^Port id:\s*(\S+)", line)
        if m:
            current["remote_interface"] = m.group(1)
        m = re.match(r"^System Capabilities:\s*(.+)", line)
        if m:
            current["capabilities"] = m.group(1).strip()
        m = re.match(r"^System Description:\s*(.+)", line)
        if m:
            current["platform"] = m.group(1).strip()
    if current:
        neighbors.append(current)
    return [n for n in neighbors if "device_id" in n]


def collect(host: str, username: str, password: str,
            port: int, use_cdp: bool, use_lldp: bool,
            timeout: int) -> dict[str, Any]:
    result: dict[str, Any] = {"host": host, "cdp": [], "lldp": [], "error": None}
    try:
        client = _connect(host, username, password, port=port, timeout=timeout)
    except Exception as exc:
        result["error"] = str(exc)
        LOG.error("Connection to %s failed: %s", host, exc)
        return result
    try:
        if use_cdp:
            raw = _ssh_exec(client, "show cdp neighbors detail", timeout=timeout)
            result["cdp"] = _parse_cdp(raw)
            LOG.info("%s: %d CDP neighbor(s)", host, len(result["cdp"]))
        if use_lldp:
            raw = _ssh_exec(client, "show lldp neighbors detail", timeout=timeout)
            result["lldp"] = _parse_lldp(raw)
            LOG.info("%s: %d LLDP neighbor(s)", host, len(result["lldp"]))
    except Exception as exc:
        result["error"] = str(exc)
        LOG.error("Command error on %s: %s", host, exc)
    finally:
        client.close()
    return result


def _print_table(results: list[dict[str, Any]]) -> None:
    col = "{:<18} {:<8} {:<30} {:<20} {:<20} {:<16}"
    header = col.format("Host", "Protocol", "Neighbor", "Local Intf", "Remote Intf", "IP Address")
    print(header)
    print("-" * len(header))
    for r in results:
        if r["error"]:
            print(f"{r['host']:<18} ERROR: {r['error']}")
            continue
        for proto, key in (("CDP", "cdp"), ("LLDP", "lldp")):
            for n in r[key]:
                print(col.format(
                    r["host"], proto,
                    n.get("device_id", ""),
                    n.get("local_interface", ""),
                    n.get("remote_interface", ""),
                    n.get("ip_address", "N/A"),
                ))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect CDP/LLDP neighbor tables from Cisco devices via SSH."
    )
    host_grp = p.add_mutually_exclusive_group(required=True)
    host_grp.add_argument("-H", "--host", help="Single device IP or hostname")
    host_grp.add_argument(
        "--hosts-file", metavar="FILE",
        help="Text file with one host per line; blank lines and # comments ignored",
    )
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--ask-pass", action="store_true", help="Prompt for password interactively")
    p.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    p.add_argument("--timeout", type=int, default=15, help="SSH/command timeout in seconds")
    p.add_argument("--cdp", action="store_true", help="Collect CDP neighbors (default if neither flag set)")
    p.add_argument("--lldp", action="store_true", help="Collect LLDP neighbors")
    p.add_argument("--json", dest="output_json", action="store_true", help="Emit JSON instead of table")
    p.add_argument("-o", "--output", metavar="FILE", help="Write output to FILE (requires --json)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = _build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.cdp and not args.lldp:
        args.cdp = True

    if args.ask_pass:
        args.password = getpass.getpass("SSH password: ")
    if not args.password:
        print("error: provide --password or --ask-pass", file=sys.stderr)
        return 1

    hosts = (
        [args.host]
        if args.host
        else [
            ln.strip()
            for ln in open(args.hosts_file)
            if ln.strip() and not ln.startswith("#")
        ]
    )

    results = [
        collect(h, args.username, args.password,
                port=args.port, use_cdp=args.cdp, use_lldp=args.lldp,
                timeout=args.timeout)
        for h in hosts
    ]

    if args.output_json:
        payload = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(payload)
            LOG.info("Written to %s", args.output)
        else:
            print(payload)
    else:
        _print_table(results)

    return 1 if any(r["error"] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
```