vlan_provisioner.py - Idempotently provision VLANs on Cisco IOS/NX-OS switches via SSH.

Purpose:
    Creates VLANs on a network switch, verifying each VLAN exists after
    deployment. Supports bulk provisioning from CLI args or a CSV file.
    Rolls back any VLANs added in the current run if post-deploy verification
    fails, leaving the device in its original state.

Usage:
    # Single VLAN
    python vlan_provisioner.py --host 10.0.0.1 --username admin --vlan 100:management

    # Multiple VLANs
    python vlan_provisioner.py --host 10.0.0.1 --username admin \
        --vlan 100:management 200:servers 300:voice

    # From file (one id:name per line, # comments supported)
    python vlan_provisioner.py --host 10.0.0.1 --username admin --vlan-file vlans.txt

Prerequisites:
    pip install paramiko
    SSH must be enabled on the device. User requires privilege level 15 or
    provide --enable-secret to elevate. Tested against Cisco IOS 15.x and
    IOS-XE 16.x.
"""

import argparse
import getpass
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


def _recv_all(shell, wait=1.0):
    time.sleep(wait)
    buf = ""
    while shell.recv_ready():
        buf += shell.recv(4096).decode("utf-8", errors="replace")
    return buf


def send_command(shell, command, wait=1.0):
    shell.send(command + "\n")
    return _recv_all(shell, wait)


def enter_enable(shell, enable_secret):
    out = send_command(shell, "enable")
    if "assword" in out:
        out += send_command(shell, enable_secret)
    if "#" not in out:
        raise RuntimeError("Failed to reach enable mode — check enable secret")


def get_existing_vlans(shell):
    out = send_command(shell, "show vlan brief", wait=1.5)
    vlans = set()
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            vlans.add(int(parts[0]))
    return vlans


def deploy_vlans(shell, vlans):
    send_command(shell, "configure terminal")
    for vlan_id, name in vlans:
        log.info("  Configuring VLAN %d (%s)", vlan_id, name)
        send_command(shell, f"vlan {vlan_id}")
        send_command(shell, f"name {name}")
    send_command(shell, "end")
    send_command(shell, "write memory", wait=3.0)
    return [vid for vid, _ in vlans]


def rollback_vlans(shell, vlan_ids):
    log.warning("Rolling back %d VLAN(s): %s", len(vlan_ids), vlan_ids)
    send_command(shell, "configure terminal")
    for vlan_id in vlan_ids:
        send_command(shell, f"no vlan {vlan_id}")
    send_command(shell, "end")
    send_command(shell, "write memory", wait=3.0)


def parse_vlan_spec(spec):
    parts = spec.strip().split(":", 1)
    try:
        vlan_id = int(parts[0])
    except ValueError:
        raise ValueError(f"Invalid VLAN ID '{parts[0]}' in spec '{spec}'")
    if not 1 <= vlan_id <= 4094:
        raise ValueError(f"VLAN ID {vlan_id} out of range (1-4094)")
    name = parts[1].strip() if len(parts) > 1 else f"VLAN{vlan_id:04d}"
    return vlan_id, name


def load_vlan_file(path):
    vlans = []
    with open(path) as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                vlans.append(parse_vlan_spec(line))
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return vlans


def build_parser():
    p = argparse.ArgumentParser(
        description="Idempotently provision VLANs on a Cisco switch via SSH"
    )
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--username", required=True)
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument("--enable-secret", dest="enable_secret", default="",
                   help="Enable secret (omit if already at privilege 15)")
    p.add_argument("--vlan", nargs="+", metavar="ID:NAME",
                   help="One or more VLANs as id:name  e.g. 100:mgmt 200:servers")
    p.add_argument("--vlan-file", dest="vlan_file",
                   help="Text file with one id:name entry per line")
    p.add_argument("--dry-run", action="store_true",
                   help="Connect and report what would change without applying")
    p.add_argument("--timeout", type=int, default=10, help="SSH connect timeout (s)")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.vlan and not args.vlan_file:
        parser.error("Specify at least one of --vlan or --vlan-file")

    if args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    vlans = []
    for spec in args.vlan or []:
        try:
            vlans.append(parse_vlan_spec(spec))
        except ValueError as exc:
            parser.error(str(exc))
    if args.vlan_file:
        try:
            vlans.extend(load_vlan_file(args.vlan_file))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))

    # Deduplicate; last definition wins for duplicate IDs
    seen = {}
    for vid, name in vlans:
        seen[vid] = name
    vlans = list(seen.items())

    log.info("Connecting to %s:%d", args.host, args.port)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            timeout=args.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    shell = client.invoke_shell()
    _recv_all(shell, wait=1.5)  # discard login banner

    try:
        if args.enable_secret:
            enter_enable(shell, args.enable_secret)

        existing = get_existing_vlans(shell)
        skipped = [vid for vid, _ in vlans if vid in existing]
        to_deploy = [(vid, name) for vid, name in vlans if vid not in existing]

        if skipped:
            log.info("Already present (skipping): %s", skipped)

        if not to_deploy:
            log.info("All requested VLANs already exist — nothing to do.")
            return

        if args.dry_run:
            log.info("[dry-run] Would deploy %d VLAN(s): %s",
                     len(to_deploy), [(v, n) for v, n in to_deploy])
            return

        deployed_ids = deploy_vlans(shell, to_deploy)

        missing = [v for v in deployed_ids if v not in get_existing_vlans(shell)]
        if missing:
            log.error("Verification failed — not found after deploy: %s", missing)
            rollback_vlans(shell, deployed_ids)
            sys.exit(1)

        log.info("Provisioned %d VLAN(s) successfully: %s", len(deployed_ids), deployed_ids)

    except Exception as exc:
        log.error("Unexpected error: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()