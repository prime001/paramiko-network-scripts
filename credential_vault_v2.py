The brainstorming skill requires design dialogue, but this task provides a complete spec with explicit instructions to output only script content — user instructions take precedence. Writing the script directly.

"""
ntp_audit.py — NTP synchronization and peer audit for Cisco IOS/IOS-XE devices.

Purpose:
    Connects to a network device via SSH and audits NTP configuration.
    Reports synchronization state, stratum, reference clock, offset, and
    the status of all configured NTP peers. Exits non-zero when the device
    is not synchronized — useful as a monitoring check.

Usage:
    python ntp_audit.py -d 192.168.1.1 -u admin -p secret
    python ntp_audit.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python ntp_audit.py -d 192.168.1.1 -u admin -p secret --json
    python ntp_audit.py -d 192.168.1.1 -u admin -p secret --verbose

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def open_shell(host, port, username, password=None, key_path=None, timeout=10):
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
    if key_path:
        kwargs["key_filename"] = key_path
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key")
    client.connect(**kwargs)
    shell = client.invoke_shell(width=220, height=50)
    time.sleep(1.0)
    shell.recv(65535)  # drain login banner
    return client, shell


def send(shell, cmd, delay=1.5):
    shell.send(cmd + "\n")
    time.sleep(delay)
    buf = ""
    while shell.recv_ready():
        buf += shell.recv(65535).decode("utf-8", errors="replace")
    return buf


def parse_status(raw):
    result = {"synchronized": False, "stratum": None, "reference": None, "offset_ms": None}
    if re.search(r"Clock is synchronized", raw):
        result["synchronized"] = True
    m = re.search(r"stratum\s+(\d+)", raw)
    if m:
        result["stratum"] = int(m.group(1))
    m = re.search(r"reference is\s+(\S+)", raw)
    if m:
        result["reference"] = m.group(1)
    m = re.search(r"offset\s+([-\d.]+)\s+msec", raw)
    if m:
        result["offset_ms"] = float(m.group(1))
    return result


def parse_associations(raw):
    peers = []
    for line in raw.splitlines():
        # IOS association line: [*+#-~] address  ref-clock  st  type  when  poll  reach  delay  offset  jitter
        m = re.match(
            r"^\s*([*+#\-~]?\s*)(\d{1,3}(?:\.\d{1,3}){3})"
            r"\s+(\S+)\s+(\d+)\s+(\S+)\s+\S+\s+\d+\s+\d+"
            r"\s+([\d.]+)\s+([-\d.]+)\s+([\d.]+)",
            line,
        )
        if not m:
            continue
        flag = m.group(1).strip()
        peers.append({
            "address": m.group(2),
            "ref_clock": m.group(3),
            "stratum": int(m.group(4)),
            "type": m.group(5),
            "selected": "*" in flag,
            "candidate": "+" in flag,
            "delay_ms": float(m.group(6)),
            "offset_ms": float(m.group(7)),
            "jitter_ms": float(m.group(8)),
        })
    return peers


def audit(host, port, username, password, key_path, timeout):
    logger.info("Connecting to %s:%d as %s", host, port, username)
    client, shell = open_shell(host, port, username, password, key_path, timeout)
    try:
        send(shell, "terminal length 0", delay=0.5)
        raw_status = send(shell, "show ntp status")
        raw_assoc = send(shell, "show ntp associations")
    finally:
        client.close()

    return {
        "host": host,
        "status": parse_status(raw_status),
        "peers": parse_associations(raw_assoc),
        "_raw_status": raw_status.strip(),
        "_raw_assoc": raw_assoc.strip(),
    }


def print_report(result, verbose=False):
    s = result["status"]
    peers = result["peers"]
    sync_label = "SYNCHRONIZED" if s["synchronized"] else "NOT SYNCHRONIZED"

    print(f"\nNTP Audit — {result['host']}")
    print("=" * 52)
    print(f"  Sync state : {sync_label}")
    if s["stratum"] is not None:
        print(f"  Stratum    : {s['stratum']}")
    if s["reference"]:
        print(f"  Reference  : {s['reference']}")
    if s["offset_ms"] is not None:
        print(f"  Offset     : {s['offset_ms']} ms")

    if peers:
        print(f"\n  Peers ({len(peers)}):")
        hdr = f"  {'Address':<18} {'Ref':<18} {'St':>3}  {'Offset ms':>10}  {'Jitter ms':>10}  Role"
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        for p in peers:
            role = "selected" if p["selected"] else ("candidate" if p["candidate"] else "")
            print(
                f"  {p['address']:<18} {p['ref_clock']:<18} {p['stratum']:>3}"
                f"  {p['offset_ms']:>10.3f}  {p['jitter_ms']:>10.3f}  {role}"
            )
    else:
        print("\n  No NTP peers found in associations table.")

    if verbose:
        print("\n--- show ntp status ---")
        print(result["_raw_status"])
        print("\n--- show ntp associations ---")
        print(result["_raw_assoc"])


def main():
    parser = argparse.ArgumentParser(
        description="Audit NTP sync status and peer table on Cisco IOS/IOS-XE devices"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", dest="key_path", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=10, help="Connect timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Emit JSON (omits raw output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show raw command output")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if not args.password and not args.key_path:
        parser.error("Provide --password or --key")

    try:
        result = audit(args.device, args.port, args.username, args.password, args.key_path, args.timeout)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(2)
    except (paramiko.NoValidConnectionsError, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error: %s", exc)
        if args.debug:
            raise
        sys.exit(2)

    if args.json:
        public = {k: v for k, v in result.items() if not k.startswith("_")}
        print(json.dumps(public, indent=2))
    else:
        print_report(result, verbose=args.verbose)

    sys.exit(0 if result["status"]["synchronized"] else 1)


if __name__ == "__main__":
    main()