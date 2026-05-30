```python
"""
vlan_provisioner.py - Cisco switch VLAN provisioning via paramiko SSH

Purpose:
    Idempotently create or rename VLANs on Cisco IOS/IOS-XE switches.
    Reads current VLAN database, applies only missing or misnamed entries,
    then verifies the result. Supports dry-run mode and optional config save.

Usage:
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret \\
        --vlans 100:DATA 200:VOICE 300:MGMT
    python vlan_provisioner.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa \\
        --vlans 100:DATA --save --dry-run

Prerequisites:
    pip install paramiko
    SSH enabled on device: ip ssh version 2
    Account requires privilege 15 or equivalent vlan-database write access
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
)
logger = logging.getLogger(__name__)

_TIMEOUT = 30
_RECV_DELAY = 0.5
_RECV_BYTES = 65535


def _connect(host, port, username, password=None, key_path=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=_TIMEOUT,
        look_for_keys=bool(key_path),
        allow_agent=False,
    )
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _open_shell(client):
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(1.0)
    shell.recv(_RECV_BYTES)
    return shell


def _send(shell, command, delay=_RECV_DELAY):
    shell.send(command + "\n")
    time.sleep(delay)
    buf = b""
    while shell.recv_ready():
        buf += shell.recv(_RECV_BYTES)
        time.sleep(0.1)
    return buf.decode("utf-8", errors="replace")


def _get_existing_vlans(shell):
    """Return {vlan_id: vlan_name} from 'show vlan brief'."""
    output = _send(shell, "show vlan brief", delay=1.2)
    vlans = {}
    for line in output.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\S+)\s+active", line, re.IGNORECASE)
        if m:
            vlans[int(m.group(1))] = m.group(2)
    return vlans


def _provision_vlans(shell, vlan_pairs):
    """Push vlan + name commands inside config mode."""
    _send(shell, "configure terminal", delay=0.5)
    for vid, name in vlan_pairs:
        _send(shell, f"vlan {vid}")
        _send(shell, f"name {name}")
        _send(shell, "exit")
    _send(shell, "end")
    time.sleep(0.4)


def _save_config(shell):
    out = _send(shell, "write memory", delay=3.5)
    return any(tok in out for tok in ("[OK]", "OK", "Building configuration"))


def _parse_vlan_args(vlan_args):
    result = []
    for entry in vlan_args:
        parts = entry.split(":", 1)
        try:
            vid = int(parts[0])
        except ValueError:
            logger.error("Invalid VLAN ID in '%s' — skipping", entry)
            continue
        if not 1 <= vid <= 4094:
            logger.error("VLAN %d out of range (1-4094) — skipping", vid)
            continue
        name = parts[1].strip() if len(parts) > 1 else f"VLAN{vid:04d}"
        result.append((vid, name))
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Idempotent VLAN provisioner for Cisco IOS/IOS-XE"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password")
    parser.add_argument("-k", "--key", metavar="PATH", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--vlans",
        nargs="+",
        required=True,
        metavar="ID:NAME",
        help="VLANs to provision, format ID:NAME (e.g. 100:DATA 200:VOICE)",
    )
    parser.add_argument(
        "--save", action="store_true", help="Run 'write memory' after changes"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show planned changes without applying"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug output")
    args = parser.parse_args()

    if not args.password and not args.key:
        parser.error("Supply --password or --key for authentication")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    targets = _parse_vlan_args(args.vlans)
    if not targets:
        logger.error("No valid VLANs to provision")
        sys.exit(1)

    logger.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = _connect(args.device, args.port, args.username, args.password, args.key)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for user '%s'", args.username)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        shell = _open_shell(client)
        _send(shell, "terminal length 0")

        existing = _get_existing_vlans(shell)
        logger.info("Device has %d active VLANs", len(existing))

        to_apply = []
        for vid, name in targets:
            if vid not in existing:
                logger.info("VLAN %d '%s' — will create", vid, name)
                to_apply.append((vid, name))
            elif existing[vid].lower() != name.lower():
                logger.info(
                    "VLAN %d — will rename '%s' -> '%s'", vid, existing[vid], name
                )
                to_apply.append((vid, name))
            else:
                logger.info("VLAN %d '%s' — already correct", vid, name)

        if not to_apply:
            logger.info("Nothing to do — all VLANs already provisioned correctly")
            return

        if args.dry_run:
            print("\nDry-run — no changes applied:")
            for vid, name in to_apply:
                action = "create" if vid not in existing else "rename"
                print(f"  [{action}] vlan {vid} name {name}")
            return

        _provision_vlans(shell, to_apply)

        verified = _get_existing_vlans(shell)
        failures = [
            f"VLAN {vid}: expected name '{name}', got '{verified.get(vid, '<missing>'"
            for vid, name in targets
            if vid not in verified or verified[vid].lower() != name.lower()
        ]
        if failures:
            for msg in failures:
                logger.error("VERIFY FAILED: %s", msg)
            sys.exit(1)

        logger.info("All %d VLANs verified successfully", len(targets))

        if args.save:
            ok = _save_config(shell)
            logger.info("Config saved") if ok else logger.warning(
                "'write memory' output ambiguous — verify manually"
            )

    finally:
        client.close()
        logger.debug("SSH session closed")


if __name__ == "__main__":
    main()
```