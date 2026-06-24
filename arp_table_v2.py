ARP table change monitor for Cisco IOS/IOS-XE network devices.

Polls the device ARP table at a configurable interval and reports additions,
removals, and MAC address changes for existing IPs. A MAC change on a stable
IP is flagged as a potential ARP spoofing event or IP conflict.

Usage:
    python arp_table_monitor.py -d 192.168.1.1 -u admin -p secret
    python arp_table_monitor.py -d 192.168.1.1 -u admin -p secret --interval 30 --count 5
    python arp_table_monitor.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa --interval 60

Prerequisites:
    pip install paramiko
    SSH access to the target device with privilege to run 'show ip arp'.
"""

import argparse
import getpass
import logging
import re
import sys
import time
from datetime import datetime

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def ssh_exec(client, command, timeout=15):
    """Run a single command over an established SSH session."""
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("Device stderr: %s", err)
    return output


def parse_arp_table(raw):
    """
    Parse 'show ip arp' output into a dict keyed by IP address.

    Returns: {ip: {"mac": str, "iface": str, "age": str}}
    Skips incomplete entries (mac == '-').
    """
    # Cisco IOS format:
    # Protocol  Address         Age (min)  Hardware Addr   Type  Interface
    # Internet  10.0.0.1              -    aabb.cc00.0100  ARPA  Gi0/0
    pattern = re.compile(
        r"^\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+|-)\s+([\da-fA-F.]+|-)\s+\S+\s+(\S+)",
        re.MULTILINE,
    )
    entries = {}
    for m in pattern.finditer(raw):
        ip, age, mac, iface = m.group(1), m.group(2), m.group(3), m.group(4)
        if mac == "-":
            continue
        entries[ip] = {"mac": mac.lower(), "iface": iface, "age": age}
    return entries


def diff_arp(previous, current):
    """
    Compare two ARP snapshots and return categorised change events.

    Returns a list of (change_type, ip, detail) tuples where change_type
    is one of: "ADDED", "REMOVED", "MAC_CHANGED".
    """
    changes = []
    prev_ips = set(previous)
    curr_ips = set(current)

    for ip in sorted(curr_ips - prev_ips):
        changes.append(("ADDED", ip, current[ip]))

    for ip in sorted(prev_ips - curr_ips):
        changes.append(("REMOVED", ip, previous[ip]))

    for ip in sorted(prev_ips & curr_ips):
        if previous[ip]["mac"] != current[ip]["mac"]:
            changes.append((
                "MAC_CHANGED",
                ip,
                {
                    "old_mac": previous[ip]["mac"],
                    "new_mac": current[ip]["mac"],
                    "iface": current[ip]["iface"],
                },
            ))
    return changes


def report_changes(changes, host):
    """Print change events to stdout with severity tags."""
    for change_type, ip, detail in changes:
        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        if change_type == "ADDED":
            print(
                f"[{ts}] {host} INFO  ADDED      "
                f"{ip:<18} mac={detail['mac']}  iface={detail['iface']}"
            )
        elif change_type == "REMOVED":
            print(
                f"[{ts}] {host} INFO  REMOVED    "
                f"{ip:<18} mac={detail['mac']}  iface={detail['iface']}"
            )
        elif change_type == "MAC_CHANGED":
            print(
                f"[{ts}] {host} WARN  MAC_CHANGED "
                f"{ip:<18} {detail['old_mac']} -> {detail['new_mac']}"
                f"  iface={detail['iface']}"
            )


def connect(host, port, username, password, key_file, timeout):
    """Establish an SSH session and return the paramiko SSHClient."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
        kwargs["look_for_keys"] = True
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def monitor(client, host, interval, count):
    """
    Poll 'show ip arp' repeatedly, diff against the previous snapshot,
    and report any changes.  Runs indefinitely when count == 0.
    """
    previous = {}
    poll = 0

    while count == 0 or poll < count:
        raw = ssh_exec(client, "show ip arp")
        current = parse_arp_table(raw)

        if not current:
            log.warning("Poll %d: no ARP entries parsed — verify device output", poll + 1)

        if poll == 0:
            log.info("Baseline established: %d ARP entries on %s", len(current), host)
        else:
            changes = diff_arp(previous, current)
            if changes:
                report_changes(changes, host)
            else:
                log.debug("Poll %d: no changes (%d entries total)", poll + 1, len(current))

        previous = current
        poll += 1

        if count == 0 or poll < count:
            time.sleep(interval)

    log.info("Done — completed %d poll(s)", poll)


def build_parser():
    p = argparse.ArgumentParser(
        description="Monitor a Cisco IOS ARP table for additions, removals, and MAC changes."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP address")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted and no key given)")
    p.add_argument("--key", dest="key_file", metavar="PATH", help="SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--interval",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Polling interval in seconds (default: 60)",
    )
    p.add_argument(
        "--count",
        type=int,
        default=0,
        metavar="N",
        help="Number of polls before exiting; 0 runs indefinitely (default: 0)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="SSH connection timeout in seconds (default: 30)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.key_file and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = connect(
            host=args.device,
            port=args.port,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    log.info(
        "Connected. Polling every %ds%s",
        args.interval,
        f", {args.count} time(s)" if args.count else " indefinitely",
    )
    try:
        monitor(client, args.device, args.interval, args.count)
    except KeyboardInterrupt:
        log.info("Interrupted")
    finally:
        client.close()