```python
#!/usr/bin/env python3
"""
routing_table_monitor.py - Detect routing table changes on network devices.

Polls a device's routing table at a configurable interval and alerts when
prefixes are added or withdrawn relative to a saved baseline. Useful for
detecting route flaps, unexpected withdrawals, or unauthorized injections
without requiring SNMP traps or a full NMS deployment.

Prerequisites:
    pip install paramiko

Usage:
    # Save baseline and begin monitoring (Ctrl-C to stop):
    python routing_table_monitor.py -d 192.168.1.1 -u admin

    # Single snapshot compared against existing baseline (exits 1 on changes):
    python routing_table_monitor.py -d 192.168.1.1 -u admin --once

    # Scope to a specific VRF and auto-update baseline on changes:
    python routing_table_monitor.py -d 192.168.1.1 -u admin --vrf MGMT --update-baseline

Supported platforms: Cisco IOS, IOS-XE, NX-OS (auto-detected).
"""

import argparse
import getpass
import logging
import re
import sys
import time
from pathlib import Path
from typing import Optional, Set

import paramiko

LOG = logging.getLogger(__name__)


def build_shell(host: str, port: int, username: str, password: str) -> paramiko.Channel:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    shell = client.invoke_shell(width=200, height=50)
    # keep a reference so the client isn't GC'd while the shell is in use
    shell._client_ref = client  # type: ignore[attr-defined]
    return shell


def recv_until_prompt(shell: paramiko.Channel, timeout: float = 30.0) -> str:
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if re.search(r"[>#]\s*$", chunk.strip()):
                break
        else:
            time.sleep(0.1)
    return output


def run_command(shell: paramiko.Channel, command: str, timeout: float = 30.0) -> str:
    shell.send(command + "\n")
    return recv_until_prompt(shell, timeout)


def extract_prefixes(raw: str) -> Set[str]:
    """Extract network/mask pairs from 'show ip route' output."""
    prefixes: Set[str] = set()
    # Matches route code lines: "O 10.1.0.0/24 [110/2] ..." or "C 10.0.0.0/8 is..."
    pattern = re.compile(
        r"^\s*[A-Z*][A-Z* ]*\s+((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)",
        re.MULTILINE,
    )
    for m in pattern.finditer(raw):
        prefixes.add(m.group(1))
    return prefixes


def load_baseline(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    lines = {ln.strip() for ln in path.read_text().splitlines() if ln.strip()}
    return lines


def save_baseline(path: Path, prefixes: Set[str]) -> None:
    path.write_text("\n".join(sorted(prefixes)) + "\n")


def report_diff(baseline: Set[str], current: Set[str]) -> bool:
    added = current - baseline
    removed = baseline - current
    if not added and not removed:
        return False
    if added:
        LOG.warning("ADDED prefixes (%d):", len(added))
        for p in sorted(added):
            LOG.warning("  + %s", p)
    if removed:
        LOG.warning("REMOVED prefixes (%d):", len(removed))
        for p in sorted(removed):
            LOG.warning("  - %s", p)
    return True


def poll(args: argparse.Namespace, baseline_path: Path) -> bool:
    """Fetch routes, compare to baseline. Returns True when changes are found."""
    LOG.info("Connecting to %s:%d", args.device, args.port)
    try:
        shell = build_shell(args.device, args.port, args.username, args.password)
    except Exception as exc:
        LOG.error("SSH connection failed: %s", exc)
        return False

    try:
        banner = recv_until_prompt(shell, timeout=5.0)
        platform = "nxos" if re.search(r"nx.?os", banner, re.IGNORECASE) else "ios"
        LOG.debug("Platform: %s", platform)

        run_command(shell, "terminal length 0")

        vrf_clause = f" vrf {args.vrf}" if args.vrf else ""
        cmd = f"show ip route{vrf_clause}"
        LOG.info("Running: %s", cmd)
        raw = run_command(shell, cmd, timeout=args.timeout)

        current = extract_prefixes(raw)
        LOG.info("%d prefixes in current table", len(current))

        baseline = load_baseline(baseline_path)
        if not baseline:
            LOG.info("No baseline — saving %d prefixes to %s", len(current), baseline_path)
            save_baseline(baseline_path, current)
            return False

        changed = report_diff(baseline, current)
        if changed and args.update_baseline:
            save_baseline(baseline_path, current)
            LOG.info("Baseline updated to reflect current state")
        elif not changed:
            LOG.info("No changes detected")
        return changed
    finally:
        shell._client_ref.close()  # type: ignore[attr-defined]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monitor routing table changes on a network device.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--vrf", help="VRF to query (default: global table)")
    p.add_argument("--baseline", help="Baseline file path (auto-named if omitted)")
    p.add_argument("--interval", type=int, default=60, help="Poll interval (seconds)")
    p.add_argument("--timeout", type=float, default=30.0, help="Per-command timeout (seconds)")
    p.add_argument("--once", action="store_true", help="Single check, exit 1 on changes")
    p.add_argument(
        "--update-baseline", action="store_true",
        help="Overwrite baseline whenever changes are detected",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    safe_host = re.sub(r"[^\w.-]", "_", args.device)
    vrf_tag = f"_{args.vrf}" if args.vrf else ""
    baseline_path = Path(args.baseline or f"{safe_host}{vrf_tag}_routes.baseline")

    if args.once:
        sys.exit(1 if poll(args, baseline_path) else 0)

    LOG.info(
        "Route monitor started — device=%s interval=%ds baseline=%s",
        args.device, args.interval, baseline_path,
    )
    try:
        while True:
            poll(args, baseline_path)
            LOG.info("Next poll in %ds", args.interval)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        LOG.info("Monitor stopped.")
```