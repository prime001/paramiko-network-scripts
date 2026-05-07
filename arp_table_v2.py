```python
"""
ARP Change Monitor — detect unauthorized devices and ARP spoofing on network infrastructure.

Connects via SSH (paramiko), fetches 'show ip arp', and compares the result against a
saved baseline or a previous poll. Useful for security auditing, change management, and
detecting rogue devices or ARP spoofing in a network segment.

Usage:
    # One-shot: print current table
    python arp_monitor.py -H 192.168.1.1 -u admin -p secret

    # Save a baseline, then diff against it on the next run
    python arp_monitor.py -H 192.168.1.1 -u admin -p secret --baseline arp_baseline.json

    # Continuously poll every 60 seconds and alert on changes
    python arp_monitor.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa --watch --interval 60

Prerequisites:
    pip install paramiko
    SSH access with at least privilege level 1 (show commands).
    Tested against Cisco IOS, IOS-XE, and NX-OS 'show ip arp' output.
"""

import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def ssh_run(host, port, username, password, key_file, command, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=bool(key_file),
        allow_agent=False,
    )
    if key_file:
        connect_kwargs["key_filename"] = key_file
    else:
        connect_kwargs["password"] = password
    try:
        client.connect(**connect_kwargs)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.debug("Device stderr: %s", err)
        return output
    finally:
        client.close()


def parse_arp_table(raw):
    """Return {ip: mac} from 'show ip arp' output (IOS/IOS-XE/NX-OS)."""
    entries = {}
    # Matches the IP and dotted-hex MAC anywhere on the line
    pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+"
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
    )
    for line in raw.splitlines():
        m = pattern.search(line)
        if m:
            entries[m.group(1)] = m.group(2).lower()
    return entries


def diff_arp(baseline, current):
    new = {ip: mac for ip, mac in current.items() if ip not in baseline}
    gone = {ip: mac for ip, mac in baseline.items() if ip not in current}
    changed = {
        ip: {"was": baseline[ip], "now": current[ip]}
        for ip in current
        if ip in baseline and current[ip] != baseline[ip]
    }
    return new, gone, changed


def report_diff(new, gone, changed, host):
    total = len(new) + len(gone) + len(changed)
    if total == 0:
        log.info("[%s] ARP table unchanged.", host)
        return
    log.warning("[%s] %d ARP change(s) detected:", host, total)
    for ip, mac in sorted(new.items()):
        log.warning("  NEW     %-18s %s", ip, mac)
    for ip, mac in sorted(gone.items()):
        log.warning("  REMOVED %-18s %s", ip, mac)
    for ip, info in sorted(changed.items()):
        log.warning("  CHANGED %-18s %s -> %s  ** possible ARP spoof **",
                    ip, info["was"], info["now"])


def load_baseline(path):
    with open(path) as f:
        data = json.load(f)
    return data.get("entries", data) if isinstance(data, dict) else data


def save_snapshot(entries, path):
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "entry_count": len(entries),
        "entries": entries,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    log.info("Snapshot saved: %s (%d entries)", path, len(entries))


def fetch_arp(args):
    raw = ssh_run(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        key_file=args.key,
        command="show ip arp",
    )
    return parse_arp_table(raw)


def build_parser():
    p = argparse.ArgumentParser(
        description="Monitor ARP table changes on a Cisco device for security auditing."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--key", metavar="FILE", help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--baseline", metavar="FILE",
        help="JSON baseline file. Created on first run; diffed on subsequent runs.",
    )
    p.add_argument(
        "--save", metavar="FILE",
        help="Save current ARP snapshot to FILE after each poll.",
    )
    p.add_argument(
        "--watch", action="store_true",
        help="Poll continuously until Ctrl-C, reporting any changes.",
    )
    p.add_argument(
        "--interval", type=int, default=120, metavar="SECS",
        help="Poll interval in watch mode, seconds (default: 120).",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main():
    args = build_parser().parse_args()

    if not args.password and not args.key:
        sys.exit("error: provide --password or --key for authentication")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        current = fetch_arp(args)
    except paramiko.AuthenticationException:
        sys.exit(f"error: authentication failed for {args.username}@{args.host}")
    except (paramiko.SSHException, OSError) as exc:
        sys.exit(f"error: {exc}")

    log.info("Fetched %d ARP entries from %s", len(current), args.host)

    if args.save:
        save_snapshot(current, args.save)

    if args.baseline:
        bpath = Path(args.baseline)
        if not bpath.exists():
            log.info("No baseline found — saving current table as baseline: %s", args.baseline)
            save_snapshot(current, args.baseline)
        else:
            baseline = load_baseline(args.baseline)
            report_diff(*diff_arp(baseline, current), args.host)
    elif not args.watch:
        print(f"{'IP Address':<18} {'MAC Address'}")
        print("-" * 36)
        for ip, mac in sorted(current.items()):
            print(f"{ip:<18} {mac}")

    if args.watch:
        log.info("Watch mode active — polling every %ds. Ctrl-C to stop.", args.interval)
        snapshot = current
        while True:
            time.sleep(args.interval)
            try:
                current = fetch_arp(args)
            except (paramiko.SSHException, OSError) as exc:
                log.warning("Poll failed (%s) — will retry next interval.", exc)
                continue
            report_diff(*diff_arp(snapshot, current), args.host)
            snapshot = current
            if args.save:
                save_snapshot(current, args.save)


if __name__ == "__main__":
    main()
```