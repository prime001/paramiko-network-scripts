The repo isn't at this path. Since the user requested output-only, here is the script:

```
"""
ARP Change Monitor — polls a device's ARP table and reports binding changes.

Connects once via SSH, sets terminal length 0, then polls 'show ip arp' at a
configurable interval.  On each poll it diffs against the previous snapshot and
reports new entries, removed entries, and IP-to-MAC rebindings.  Rebindings are
optionally surfaced at WARNING level because they can indicate ARP spoofing.

Usage:
    python arp_monitor.py -H 192.168.1.1 -u admin
    python arp_monitor.py -H 192.168.1.1 -u admin -p secret --interval 30 --count 10
    python arp_monitor.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa --warn-on-rebind

Prerequisites:
    pip install paramiko
    Target device must support 'show ip arp' (Cisco IOS / IOS-XE / NX-OS).
"""

import argparse
import getpass
import logging
import re
import sys
import time
from typing import Dict, List, Optional, Tuple

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

# Matches Cisco 'show ip arp' lines:  Internet  10.0.0.1  5  aabb.cc00.0100  ARPA  Gi0/0
_ARP_RE = re.compile(
    r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+"
    r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+",
    re.IGNORECASE,
)


def _recv_until_prompt(channel: paramiko.Channel, timeout: float = 12.0) -> str:
    buf = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            buf += channel.recv(65535).decode("utf-8", errors="replace")
            stripped = buf.rstrip()
            if stripped.endswith("#") or stripped.endswith(">"):
                break
        else:
            time.sleep(0.05)
    return buf


def open_shell(client: paramiko.SSHClient) -> paramiko.Channel:
    shell = client.invoke_shell(width=220, height=50)
    time.sleep(0.8)
    shell.recv(65535)  # drain login banner
    shell.send("terminal length 0\n")
    _recv_until_prompt(shell)
    return shell


def collect_arp(shell: paramiko.Channel) -> Dict[str, str]:
    """Return {ip: mac} from 'show ip arp'."""
    shell.send("show ip arp\n")
    output = _recv_until_prompt(shell)
    table: Dict[str, str] = {}
    for line in output.splitlines():
        m = _ARP_RE.search(line)
        if m:
            table[m.group("ip")] = m.group("mac").lower()
    return table


def diff_arp(
    prev: Dict[str, str], curr: Dict[str, str]
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], List[Tuple[str, str, str]]]:
    added = [(ip, mac) for ip, mac in curr.items() if ip not in prev]
    removed = [(ip, mac) for ip, mac in prev.items() if ip not in curr]
    changed = [
        (ip, prev[ip], curr[ip])
        for ip in curr
        if ip in prev and prev[ip] != curr[ip]
    ]
    return added, removed, changed


def connect(
    host: str,
    port: int,
    username: str,
    password: Optional[str],
    key_file: Optional[str],
    timeout: float,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=bool(key_file),
        allow_agent=False,
    )
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Poll a device's ARP table and report binding changes."
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument(
        "-p", "--password", default=None, help="SSH password (prompted if omitted)"
    )
    p.add_argument("--key", dest="key_file", default=None, help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between polls (default: 60)",
    )
    p.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of polls before exiting; 0 = run forever (default: 0)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="SSH connect timeout in seconds (default: 10)",
    )
    p.add_argument(
        "--warn-on-rebind",
        action="store_true",
        help="Log IP-to-MAC rebindings at WARNING level (potential ARP spoofing)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.key_file and args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = connect(
            args.host, args.port, args.username,
            args.password, args.key_file, args.timeout,
        )
        shell = open_shell(client)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    prev: Optional[Dict[str, str]] = None
    poll = 0

    try:
        while args.count == 0 or poll < args.count:
            poll += 1
            try:
                curr = collect_arp(shell)
            except (paramiko.SSHException, OSError) as exc:
                log.warning("Lost connection (%s) — reconnecting", exc)
                try:
                    client.close()
                    client = connect(
                        args.host, args.port, args.username,
                        args.password, args.key_file, args.timeout,
                    )
                    shell = open_shell(client)
                    curr = collect_arp(shell)
                except Exception as exc2:
                    log.error("Reconnect failed: %s", exc2)
                    return 1

            log.info("Poll %d: %d entries", poll, len(curr))

            if prev is not None:
                added, removed, changed = diff_arp(prev, curr)
                for ip, mac in added:
                    log.info("  NEW     %s -> %s", ip, mac)
                for ip, mac in removed:
                    log.info("  REMOVED %s (was %s)", ip, mac)
                for ip, old_mac, new_mac in changed:
                    level = logging.WARNING if args.warn_on_rebind else logging.INFO
                    log.log(
                        level,
                        "  REBIND  %s: %s -> %s  [check for ARP spoofing]",
                        ip, old_mac, new_mac,
                    )
                if not (added or removed or changed):
                    log.debug("  No changes.")

            prev = curr

            if args.count == 0 or poll < args.count:
                log.debug("Sleeping %ds", args.interval)
                time.sleep(args.interval)

    except KeyboardInterrupt:
        log.info("Interrupted.")
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
```