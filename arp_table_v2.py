"""
arp_table.py - Retrieve and parse ARP table from network devices via SSH.

Purpose:
    Connects to a network device over SSH using Paramiko, retrieves the ARP
    table, parses entries into structured data, and outputs results as a
    formatted table or JSON. Useful for IP-to-MAC mapping, troubleshooting
    duplicate IPs, and auditing Layer 2/3 adjacencies.

Usage:
    python arp_table.py -H 192.168.1.1 -u admin -p secret
    python arp_table.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa --json
    python arp_table.py -H 192.168.1.1 -u admin -p secret --filter 10.0.0.

Prerequisites:
    pip install paramiko
    SSH access to target device (Cisco IOS/IOS-XE/NX-OS supported)
"""

import argparse
import json
import logging
import re
import sys
import getpass

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

ARP_PATTERNS = [
    # Cisco IOS: Internet  10.0.0.1  5  aabb.cc00.0100  ARPA  GigabitEthernet0/0
    re.compile(
        r"Internet\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<age>\d+|-)\s+"
        r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(?P<iface>\S+)",
        re.IGNORECASE,
    ),
    # NX-OS: 10.0.0.1  00:50:56:ab:cd:ef  0:05:11  GigE1/1  base
    re.compile(
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<mac>[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})"
        r"\s+\S+\s+(?P<iface>\S+)",
        re.IGNORECASE,
    ),
]


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to xx:xx:xx:xx:xx:xx format."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        return mac
    return ":".join(digits[i:i+2] for i in range(0, 12, 2)).lower()


def parse_arp_output(output: str) -> list[dict]:
    entries = []
    for line in output.splitlines():
        for pattern in ARP_PATTERNS:
            m = pattern.search(line)
            if m:
                entry = {
                    "ip": m.group("ip"),
                    "mac": normalize_mac(m.group("mac")),
                    "interface": m.group("iface"),
                }
                try:
                    entry["age"] = m.group("age")
                except IndexError:
                    entry["age"] = "-"
                entries.append(entry)
                break
    return entries


def ssh_run(host: str, port: int, username: str, password: str | None,
            key_path: str | None, command: str, timeout: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("Provide either --password or --key for authentication.")

    try:
        log.info("Connecting to %s:%d as %s", host, port, username)
        client.connect(**connect_kwargs)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.warning("stderr from device: %s", err)
        return output
    finally:
        client.close()


def print_table(entries: list[dict]) -> None:
    if not entries:
        print("No ARP entries found.")
        return
    header = f"{'IP Address':<18} {'MAC Address':<20} {'Interface':<24} {'Age'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(f"{e['ip']:<18} {e['mac']:<20} {e['interface']:<24} {e.get('age', '-')}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Retrieve and parse ARP table from a network device via SSH."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("--key", metavar="PATH", help="Path to SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    p.add_argument("--command", default="show arp", help="ARP command to run (default: 'show arp')")
    p.add_argument("--filter", metavar="PREFIX", help="Filter output to IPs containing this prefix")
    p.add_argument("--json", action="store_true", help="Output results as JSON")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        raw = ssh_run(
            host=args.host,
            port=args.port,
            username=args.username,
            password=password,
            key_path=args.key,
            command=args.command,
            timeout=args.timeout,
        )
    except (paramiko.AuthenticationException, paramiko.SSHException) as exc:
        log.error("SSH error: %s", exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    entries = parse_arp_output(raw)
    log.info("Parsed %d ARP entries from %s", len(entries), args.host)

    if args.filter:
        entries = [e for e in entries if args.filter in e["ip"]]
        log.info("%d entries after filtering by '%s'", len(entries), args.filter)

    if args.json:
        print(json.dumps(entries, indent=2))
    else:
        print_table(entries)