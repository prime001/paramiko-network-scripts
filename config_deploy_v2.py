vlan_provisioner.py — Deploy and verify VLAN configuration across Cisco IOS/IOS-XE switches.

Purpose:
    Create or remove a single VLAN on one or more switches via SSH.  After each
    change the script reads 'show vlan brief' and verifies the VLAN is present
    (or absent), reporting per-device results and exiting non-zero on any failure.

Usage:
    # Create VLAN 100 on two switches
    python vlan_provisioner.py --hosts 10.0.0.1 10.0.0.2 \
        --username admin --password secret \
        --vlan-id 100 --vlan-name CORP_DATA

    # Remove VLAN 100
    python vlan_provisioner.py --hosts 10.0.0.1 \
        --username admin --password secret \
        --vlan-id 100 --remove

    # Preview without making changes
    python vlan_provisioner.py --hosts 10.0.0.1 \
        --username admin --password secret \
        --vlan-id 100 --vlan-name CORP_DATA --dry-run

Prerequisites:
    pip install paramiko
    SSH enabled on target devices; credentials require privilege 15.
"""

import argparse
import logging
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_BUFFER = 65535
_PROMPT_TIMEOUT = 4.0


def _recv_until(shell, marker="#", timeout=_PROMPT_TIMEOUT):
    buf = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if shell.recv_ready():
            buf += shell.recv(_BUFFER).decode("utf-8", errors="replace")
            if marker in buf:
                break
        else:
            time.sleep(0.05)
    return buf


def _send(shell, cmd, marker="#", timeout=_PROMPT_TIMEOUT):
    shell.send(cmd + "\n")
    return _recv_until(shell, marker, timeout)


def _open_shell(host, port, username, password, connect_timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=connect_timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    shell = client.invoke_shell(width=220, height=50)
    _recv_until(shell)
    return client, shell


def _vlan_present(show_output, vlan_id):
    target = str(vlan_id)
    for line in show_output.splitlines():
        first = line.strip().split()
        if first and first[0] == target:
            return True
    return False


def provision(host, port, username, password, vlan_id, vlan_name, remove, dry_run, connect_timeout):
    """Connect to *host* and create or remove *vlan_id*. Returns (ok, message)."""
    try:
        client, shell = _open_shell(host, port, username, password, connect_timeout)
    except paramiko.AuthenticationException:
        return False, "authentication failed"
    except Exception as exc:
        return False, f"connection error: {exc}"

    try:
        _send(shell, "terminal length 0")
        show_before = _send(shell, "show vlan brief")
        already_present = _vlan_present(show_before, vlan_id)

        if dry_run:
            if remove:
                note = "not present — nothing to do" if not already_present else "would be removed"
            else:
                note = "already present" if already_present else f"would be added (name={vlan_name or 'unset'})"
            return True, f"[DRY-RUN] VLAN {vlan_id}: {note}"

        _send(shell, "configure terminal", marker="(config)#")
        if remove:
            _send(shell, f"no vlan {vlan_id}", marker="(config)#")
        else:
            _send(shell, f"vlan {vlan_id}", marker="(config-vlan)#")
            if vlan_name:
                _send(shell, f"name {vlan_name}", marker="(config-vlan)#")
            _send(shell, "exit", marker="(config)#")

        _send(shell, "end")
        _send(shell, "write memory", timeout=20)

        show_after = _send(shell, "show vlan brief")
        now_present = _vlan_present(show_after, vlan_id)

        if remove and not now_present:
            return True, f"VLAN {vlan_id} removed and verified absent"
        if remove and now_present:
            return False, f"VLAN {vlan_id} still present after removal"
        if not remove and now_present:
            return True, f"VLAN {vlan_id} provisioned and verified present"
        return False, f"VLAN {vlan_id} not found in 'show vlan brief' after provisioning"

    except Exception as exc:
        return False, f"error during provisioning: {exc}"
    finally:
        client.close()


def build_parser():
    p = argparse.ArgumentParser(
        description="Create or remove a VLAN on one or more Cisco IOS/IOS-XE switches."
    )
    p.add_argument("--hosts", nargs="+", required=True, metavar="HOST",
                   help="Device IP(s) or hostnames")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--vlan-id", required=True, type=int, metavar="ID",
                   help="VLAN ID (1–4094)")
    p.add_argument("--vlan-name", default="", metavar="NAME",
                   help="VLAN name (optional when creating)")
    p.add_argument("--remove", action="store_true",
                   help="Remove VLAN instead of creating it")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=10, metavar="SEC",
                   help="TCP connect timeout in seconds (default: 10)")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would change without touching the device")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if not 1 <= args.vlan_id <= 4094:
        log.error("--vlan-id must be between 1 and 4094")
        sys.exit(1)

    failures = []
    for host in args.hosts:
        log.info("%-20s  processing …", host)
        ok, msg = provision(
            host=host,
            port=args.port,
            username=args.username,
            password=args.password,
            vlan_id=args.vlan_id,
            vlan_name=args.vlan_name,
            remove=args.remove,
            dry_run=args.dry_run,
            connect_timeout=args.timeout,
        )
        level = logging.INFO if ok else logging.ERROR
        log.log(level, "%-20s  %s", host, msg)
        if not ok:
            failures.append(host)

    if failures:
        log.error("%d device(s) failed: %s", len(failures), ", ".join(failures))
        sys.exit(1)

    log.info("all %d device(s) completed successfully", len(args.hosts))