The user's instruction says "Output ONLY the script content" — I'll write a practical NTP configuration deployment script that's not covered by any existing scripts in the repo.

"""
ntp_deploy.py - NTP Server Configuration Deployment and Verification

Deploy NTP server entries and optional MD5 authentication to Cisco IOS/IOS-XE
devices over SSH. After applying the configuration, polls `show ntp status`
until the clock is synchronized or the verification timeout expires.

Usage:
    python ntp_deploy.py --host 192.168.1.1 --user admin --password secret \
        --ntp-servers 10.0.0.1 10.0.0.2 [--auth-key 1 --auth-secret mykey] \
        [--enable-password secret] [--verify-timeout 90] [--dry-run]

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device (ip ssh version 2).
"""

import argparse
import logging
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def ssh_connect(host, port, username, password, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def send(shell, command, wait=0.5):
    shell.send(command + "\n")
    time.sleep(wait)
    buf = ""
    while shell.recv_ready():
        buf += shell.recv(4096).decode("utf-8", errors="replace")
    return buf


def enter_enable(shell, enable_password):
    out = send(shell, "enable", wait=0.5)
    if "Password" in out and enable_password:
        send(shell, enable_password, wait=0.5)


def build_commands(ntp_servers, auth_key, auth_secret):
    cmds = ["configure terminal"]
    if auth_key and auth_secret:
        cmds.append("ntp authenticate")
        cmds.append(f"ntp authentication-key {auth_key} md5 {auth_secret}")
        cmds.append(f"ntp trusted-key {auth_key}")
        for srv in ntp_servers:
            cmds.append(f"ntp server {srv} key {auth_key}")
    else:
        for srv in ntp_servers:
            cmds.append(f"ntp server {srv}")
    cmds += ["end", "write memory"]
    return cmds


def apply_config(shell, commands, dry_run=False):
    if dry_run:
        log.info("Dry run — commands that would be sent:")
        for c in commands:
            log.info("  %s", c)
        return True

    for cmd in commands:
        out = send(shell, cmd, wait=0.6)
        log.debug(">>> %s\n%s", cmd, out.strip())
        if "Invalid input" in out or "% Error" in out or "% Ambiguous" in out:
            log.error("Command rejected: %r\nDevice output: %s", cmd, out.strip())
            return False
    return True


def verify_sync(shell, timeout, poll=5):
    log.info("Waiting up to %ds for NTP synchronization...", timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = send(shell, "show ntp status", wait=1.0)
        if "Clock is synchronized" in out:
            log.info("Clock is synchronized.")
            return True
        remaining = int(deadline - time.time())
        log.debug("Not yet synchronized (%ds remaining).", remaining)
        time.sleep(poll)

    assoc = send(shell, "show ntp associations", wait=1.0)
    log.warning("NTP not synchronized within timeout.\n%s", assoc.strip())
    return False


def parse_args():
    p = argparse.ArgumentParser(
        description="Deploy NTP configuration to a Cisco IOS/IOS-XE device"
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    p.add_argument("--user", required=True, help="SSH username")
    p.add_argument("--password", required=True, help="SSH password")
    p.add_argument("--enable-password", help="Enable-mode password (if required)")
    p.add_argument(
        "--ntp-servers",
        nargs="+",
        required=True,
        metavar="IP",
        help="One or more NTP server IPs to configure",
    )
    p.add_argument("--auth-key", metavar="ID", help="NTP authentication key ID")
    p.add_argument("--auth-secret", metavar="SECRET", help="NTP MD5 key secret")
    p.add_argument(
        "--verify-timeout",
        type=int,
        default=60,
        metavar="SECS",
        help="Seconds to wait for sync confirmation (default 60)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without applying them",
    )
    p.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip post-deploy sync verification",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    if bool(args.auth_key) != bool(args.auth_secret):
        log.error("--auth-key and --auth-secret must be provided together")
        sys.exit(1)

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = ssh_connect(args.host, args.port, args.user, args.password)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(4096)

        if args.enable_password:
            enter_enable(shell, args.enable_password)

        send(shell, "terminal length 0", wait=0.3)

        commands = build_commands(args.ntp_servers, args.auth_key, args.auth_secret)
        log.info("Deploying NTP servers: %s", ", ".join(args.ntp_servers))

        if not apply_config(shell, commands, dry_run=args.dry_run):
            log.error("Deployment failed — check device output above.")
            sys.exit(1)

        if args.dry_run:
            sys.exit(0)

        log.info("Configuration saved.")

        if not args.no_verify:
            synced = verify_sync(shell, args.verify_timeout)
            sys.exit(0 if synced else 2)

    except KeyboardInterrupt:
        log.info("Interrupted.")
        sys.exit(130)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)
    finally:
        client.close()