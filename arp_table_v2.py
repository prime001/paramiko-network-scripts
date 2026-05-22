Writing an ARP table change monitor script — since both v1 and v2 already cover basic ARP table retrieval, I'll implement continuous ARP monitoring with change detection (new entries, removed entries, IP-MAC reassignments).

```python
"""
arp_monitor.py — ARP Table Change Monitor via SSH/Paramiko

Polls a network device's ARP table at configurable intervals and reports
new entries, removed entries, and IP-to-MAC reassignments (potential ARP
spoofing indicators). Useful for network forensics, change auditing, and
detecting unauthorized devices.

Usage:
    python arp_monitor.py -H 192.168.1.1 -u admin -p secret
    python arp_monitor.py -H 192.168.1.1 -u admin -p secret --interval 30 --count 5
    python arp_monitor.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa --json

Prerequisites:
    pip install paramiko
    Device must support 'show arp' (Cisco IOS/NX-OS) or 'show ip arp'
"""

import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr: %s", err)
    return output


def connect(host: str, port: int, username: str, password: str | None,
            key_path: str | None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=username, timeout=10)
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def parse_arp_table(raw: str) -> dict[str, str]:
    """Return {ip: mac} from 'show arp' output (Cisco IOS/NX-OS)."""
    entries: dict[str, str] = {}
    # Matches lines like: Internet  10.0.0.1  5  aabb.cc00.0100  ARPA  Gi0/0
    pattern = re.compile(
        r"Internet\s+([\d.]+)\s+\S+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
    )
    for match in pattern.finditer(raw):
        ip, mac = match.group(1), match.group(2).lower()
        entries[ip] = mac
    return entries


def diff_arp(previous: dict[str, str], current: dict[str, str]) -> dict:
    added = {ip: mac for ip, mac in current.items() if ip not in previous}
    removed = {ip: mac for ip, mac in previous.items() if ip not in current}
    reassigned = {
        ip: {"old": previous[ip], "new": current[ip]}
        for ip in current
        if ip in previous and previous[ip] != current[ip]
    }
    return {"added": added, "removed": removed, "reassigned": reassigned}


def print_diff(changes: dict, timestamp: str, as_json: bool) -> None:
    if not any(changes.values()):
        return

    if as_json:
        print(json.dumps({"timestamp": timestamp, **changes}, indent=2))
        return

    print(f"\n[{timestamp}] ARP table changes detected:")
    for ip, mac in changes["added"].items():
        print(f"  + NEW      {ip:<18} {mac}")
    for ip, mac in changes["removed"].items():
        print(f"  - REMOVED  {ip:<18} {mac}")
    for ip, info in changes["reassigned"].items():
        print(f"  ! REASSIGN {ip:<18} {info['old']} -> {info['new']}")


def monitor(args: argparse.Namespace) -> None:
    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = connect(args.host, args.port, args.username,
                         args.password, args.key)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    log.info("Connected — polling every %ds (count=%s)",
             args.interval, args.count or "unlimited")

    previous: dict[str, str] = {}
    iteration = 0

    try:
        while True:
            try:
                raw = ssh_exec(client, "show arp")
            except Exception as exc:
                log.warning("Command failed: %s — reconnecting", exc)
                try:
                    client.close()
                    client = connect(args.host, args.port, args.username,
                                     args.password, args.key)
                    raw = ssh_exec(client, "show arp")
                except Exception as exc2:
                    log.error("Reconnect failed: %s", exc2)
                    break

            current = parse_arp_table(raw)
            if not current:
                log.warning("No ARP entries parsed — check device output format")

            ts = datetime.now().isoformat(timespec="seconds")

            if iteration == 0:
                log.info("Baseline: %d ARP entries loaded", len(current))
            else:
                changes = diff_arp(previous, current)
                print_diff(changes, ts, args.json)
                if not any(changes.values()):
                    log.debug("[%s] No changes (%d entries)", ts, len(current))

            previous = current
            iteration += 1

            if args.count and iteration >= args.count:
                log.info("Reached poll count limit (%d), exiting", args.count)
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        log.info("Interrupted by user")
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor ARP table changes on a network device via SSH"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password")
    parser.add_argument("-k", "--key", help="Path to SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--interval", type=int, default=60,
        help="Polling interval in seconds (default: 60)"
    )
    parser.add_argument(
        "--count", type=int, default=0,
        help="Number of polls before exiting; 0 = unlimited (default: 0)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output changes as JSON instead of plain text"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if not args.password and not args.key:
        parser.error("Provide --password or --key for authentication")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    monitor(args)


if __name__ == "__main__":
    main()
```