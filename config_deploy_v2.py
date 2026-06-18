```python
"""
vlan_provisioner.py - VLAN provisioning and verification for Cisco IOS/IOS-XE switches.

Purpose:
    Create, delete, or verify VLANs on Cisco IOS/IOS-XE switches via SSH.
    Optionally adds a newly created VLAN to a specified trunk interface.

Usage:
    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret create 100 --name SERVERS
    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret create 100 --name MGMT --trunk Gi0/1
    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret verify 100 200 300
    python vlan_provisioner.py -H 192.168.1.1 -u admin -p secret delete 100

Prerequisites:
    pip install paramiko
    SSH access to Cisco IOS/IOS-XE device with privilege level 15
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
log = logging.getLogger(__name__)

RECV_TIMEOUT = 2.0
BUFFER_SIZE = 65535


def open_shell(client: paramiko.SSHClient) -> paramiko.Channel:
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(0.5)
    shell.recv(BUFFER_SIZE)
    return shell


def send_command(shell: paramiko.Channel, command: str, wait: float = RECV_TIMEOUT) -> str:
    shell.send(command + "\n")
    time.sleep(wait)
    output = b""
    while shell.recv_ready():
        output += shell.recv(BUFFER_SIZE)
    return output.decode("utf-8", errors="replace")


def enter_config_mode(shell: paramiko.Channel) -> None:
    send_command(shell, "terminal length 0", wait=0.5)
    out = send_command(shell, "configure terminal")
    if "Enter configuration commands" not in out and "#" not in out:
        raise RuntimeError(f"Failed to enter config mode: {out!r}")


def exit_config_mode(shell: paramiko.Channel) -> None:
    send_command(shell, "end", wait=0.5)


def get_vlan_database(shell: paramiko.Channel) -> dict:
    """Return {vlan_id: vlan_name} parsed from 'show vlan brief'."""
    out = send_command(shell, "show vlan brief", wait=1.5)
    vlans = {}
    for line in out.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+active", line)
        if m:
            vlans[int(m.group(1))] = m.group(2)
    return vlans


def create_vlan(
    shell: paramiko.Channel,
    vlan_id: int,
    name: str | None,
    trunk: str | None,
) -> bool:
    enter_config_mode(shell)

    send_command(shell, f"vlan {vlan_id}", wait=0.5)
    if name:
        out = send_command(shell, f"name {name}", wait=0.5)
        if "%" in out:
            log.error("Error setting VLAN name: %s", out.strip())
            exit_config_mode(shell)
            return False
    send_command(shell, "exit", wait=0.5)

    if trunk:
        send_command(shell, f"interface {trunk}", wait=0.5)
        out = send_command(shell, f"switchport trunk allowed vlan add {vlan_id}", wait=0.5)
        if "%" in out:
            log.warning("Could not add VLAN %d to trunk %s: %s", vlan_id, trunk, out.strip())
        send_command(shell, "exit", wait=0.5)

    exit_config_mode(shell)

    vlans = get_vlan_database(shell)
    if vlan_id in vlans:
        log.info("VLAN %d (%s) created successfully", vlan_id, vlans[vlan_id])
        return True
    log.error("VLAN %d not found in database after creation", vlan_id)
    return False


def delete_vlan(shell: paramiko.Channel, vlan_id: int) -> bool:
    vlans = get_vlan_database(shell)
    if vlan_id not in vlans:
        log.warning("VLAN %d does not exist — nothing to delete", vlan_id)
        return True

    enter_config_mode(shell)
    out = send_command(shell, f"no vlan {vlan_id}")
    if "%" in out:
        log.error("Error deleting VLAN %d: %s", vlan_id, out.strip())
        exit_config_mode(shell)
        return False
    exit_config_mode(shell)

    vlans = get_vlan_database(shell)
    if vlan_id not in vlans:
        log.info("VLAN %d deleted successfully", vlan_id)
        return True
    log.error("VLAN %d still present after delete attempt", vlan_id)
    return False


def verify_vlans(shell: paramiko.Channel, vlan_ids: list[int]) -> dict:
    vlans = get_vlan_database(shell)
    results = {}
    for vid in vlan_ids:
        present = vid in vlans
        results[vid] = {"present": present, "name": vlans.get(vid, "")}
        status = "OK     " if present else "MISSING"
        detail = f"({vlans[vid]})" if present else ""
        log.info("VLAN %4d: %s %s", vid, status, detail)
    return results


def connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
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
    return client


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision and verify VLANs on Cisco IOS/IOS-XE switches"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

    sub = parser.add_subparsers(dest="action", required=True)

    c = sub.add_parser("create", help="Create a VLAN")
    c.add_argument("vlan_id", type=int, help="VLAN ID (1-4094)")
    c.add_argument("--name", help="VLAN name")
    c.add_argument("--trunk", metavar="INTERFACE", help="Add VLAN to this trunk interface after creation")

    d = sub.add_parser("delete", help="Delete a VLAN")
    d.add_argument("vlan_id", type=int, help="VLAN ID to remove")

    v = sub.add_parser("verify", help="Verify one or more VLANs exist")
    v.add_argument("vlan_ids", type=int, nargs="+", help="VLAN IDs to check")

    return parser


def main() -> None:
    args = build_parser().parse_args()

    try:
        log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
        client = connect(args.host, args.port, args.username, args.password)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        shell = open_shell(client)

        if args.action == "create":
            if not (1 <= args.vlan_id <= 4094):
                log.error("VLAN ID must be between 1 and 4094")
                sys.exit(1)
            ok = create_vlan(shell, args.vlan_id, args.name, args.trunk)
            sys.exit(0 if ok else 1)

        elif args.action == "delete":
            ok = delete_vlan(shell, args.vlan_id)
            sys.exit(0 if ok else 1)

        elif args.action == "verify":
            results = verify_vlans(shell, args.vlan_ids)
            missing = [vid for vid, r in results.items() if not r["present"]]
            if missing:
                log.warning("Missing VLANs: %s", missing)
                sys.exit(1)
            log.info("All %d VLANs verified present", len(results))

    except RuntimeError as exc:
        log.error("%s", exc)
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
```