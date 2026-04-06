#!/usr/bin/env python3
"""
config_deploy.py — Batch configuration deployer for network devices.

Purpose:
    Connects to one or more network devices via SSH and pushes a set of
    configuration commands read from a file.  Each command is sent
    interactively, the device output is captured, and a per-device
    deployment report is written to disk.

Usage:
    # Single device
    python config_deploy.py -d 192.168.1.1 -u admin -c commands.txt

    # Multiple devices from inventory file (one IP/hostname per line)
    python config_deploy.py -i inventory.txt -u admin -c commands.txt \
        --password-file .secret --output-dir ./reports

    # Use key-based auth and a non-standard port
    python config_deploy.py -d 10.0.0.1 -u netops -k ~/.ssh/id_rsa \
        -c commands.txt -p 2222

Prerequisites:
    pip install paramiko
    Python 3.8+
    SSH access to target devices (password or key-based)
"""

import argparse
import getpass
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("config_deploy")


def load_commands(path: str) -> list[str]:
    """Return non-empty, non-comment lines from a commands file."""
    cmds = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                cmds.append(line)
    if not cmds:
        raise ValueError(f"No commands found in {path}")
    return cmds


def load_inventory(path: str) -> list[str]:
    """Return hostnames/IPs from an inventory file (one per line)."""
    hosts = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def deploy_to_device(
    host: str,
    port: int,
    username: str,
    password: str | None,
    key_path: str | None,
    commands: list[str],
    inter_cmd_delay: float = 0.5,
    timeout: int = 30,
) -> dict:
    """
    Open an SSH shell to *host*, send each command, and return a result dict.

    Returns:
        {
            "host": str,
            "success": bool,
            "output": str,          # combined device output
            "error": str | None,
        }
    """
    result = {"host": host, "success": False, "output": "", "error": None}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict = {
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

    try:
        logger.info("[%s] Connecting…", host)
        client.connect(**connect_kwargs)

        shell = client.invoke_shell(width=200, height=50)
        shell.settimeout(timeout)
        time.sleep(1)
        _drain(shell)  # clear banner / MOTD

        collected = []
        for cmd in commands:
            logger.debug("[%s] Sending: %s", host, cmd)
            shell.send(cmd + "\n")
            time.sleep(inter_cmd_delay)
            chunk = _drain(shell)
            collected.append(f">>> {cmd}\n{chunk}")

        result["output"] = "\n".join(collected)
        result["success"] = True
        logger.info("[%s] Deployment complete (%d commands).", host, len(commands))

    except paramiko.AuthenticationException as exc:
        result["error"] = f"Authentication failed: {exc}"
        logger.error("[%s] %s", host, result["error"])
    except paramiko.SSHException as exc:
        result["error"] = f"SSH error: {exc}"
        logger.error("[%s] %s", host, result["error"])
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
        logger.error("[%s] %s", host, result["error"])
    finally:
        client.close()

    return result


def _drain(shell: paramiko.Channel, read_timeout: float = 0.4) -> str:
    """Read all available data from an interactive shell channel."""
    buf = []
    shell.settimeout(read_timeout)
    try:
        while True:
            chunk = shell.recv(4096)
            if not chunk:
                break
            buf.append(chunk.decode("utf-8", errors="replace"))
    except Exception:
        pass
    return "".join(buf)


def write_report(result: dict, output_dir: str) -> None:
    """Write a per-device deployment report to *output_dir*."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = result["host"].replace(".", "_").replace(":", "_")
    fname = os.path.join(output_dir, f"{safe_host}_{stamp}.txt")
    with open(fname, "w") as fh:
        fh.write(f"Host   : {result['host']}\n")
        fh.write(f"Status : {'SUCCESS' if result['success'] else 'FAILED'}\n")
        if result["error"]:
            fh.write(f"Error  : {result['error']}\n")
        fh.write("\n--- Device Output ---\n")
        fh.write(result["output"])
    logger.info("[%s] Report written → %s", result["host"], fname)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy configuration commands to network devices via SSH.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single target device IP/hostname")
    target.add_argument("-i", "--inventory", help="File with one device per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-c", "--commands", required=True, help="File of commands to deploy")

    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--password-file", help="File containing the SSH password")
    auth.add_argument("-k", "--key", help="Path to SSH private key")

    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between commands (default: 0.5)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH connection timeout in seconds")
    parser.add_argument("--output-dir", default="./deploy_reports", help="Directory for report files")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without connecting")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    commands = load_commands(args.commands)
    hosts = [args.device] if args.device else load_inventory(args.inventory)

    if not hosts:
        logger.error("No target devices found.")
        return 1

    if args.dry_run:
        print(f"DRY RUN — would deploy {len(commands)} command(s) to {len(hosts)} device(s):")
        for cmd in commands:
            print(f"  {cmd}")
        return 0

    password = None
    if not args.key:
        if args.password_file:
            with open(args.password_file) as fh:
                password = fh.read().strip()
        else:
            password = getpass.getpass(f"SSH password for {args.username}: ")

    failures = 0
    for host in hosts:
        result = deploy_to_device(
            host=host,
            port=args.port,
            username=args.username,
            password=password,
            key_path=args.key,
            commands=commands,
            inter_cmd_delay=args.delay,
            timeout=args.timeout,
        )
        write_report(result, args.output_dir)
        if not result["success"]:
            failures += 1

    total = len(hosts)
    logger.info("Done: %d/%d succeeded, %d failed.", total - failures, total, failures)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())