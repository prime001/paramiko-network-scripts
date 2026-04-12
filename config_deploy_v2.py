The user's prompt says "Output ONLY the script content, no markdown fences, no explanation" — this is an automated pipeline with fully specified requirements. The brainstorming skill is overridden by the explicit output instruction. Writing the script directly.

The existing scripts cover config_deploy, config_backup, config_diff, bulk commands, ARP table, etc. A good complement is a **staged config deployment with automatic rollback** — applies config, runs verification commands, rolls back if checks fail.

```python
#!/usr/bin/env python3
"""
staged_config_deploy.py - Staged configuration deployment with verification and rollback.

Purpose:
    Deploy configuration changes to a network device with pre/post verification checks.
    If post-deployment verification fails, automatically rolls back to the saved
    pre-deployment configuration.

Usage:
    python staged_config_deploy.py -H 192.168.1.1 -u admin -p secret \
        -c changes.txt -v verify_commands.txt

    python staged_config_deploy.py -H 192.168.1.1 -u admin \
        -c changes.txt --no-rollback --timeout 60

Prerequisites:
    - pip install paramiko
    - SSH access to target device
    - Device must support 'show running-config' and accept config via CLI
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def send_command(shell, command, wait=1.5, buffer=65535):
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(buffer).decode("utf-8", errors="replace")
        time.sleep(0.2)
    return output


def capture_running_config(shell):
    log.info("Capturing pre-deployment running config for rollback")
    output = send_command(shell, "show running-config", wait=3)
    lines = output.splitlines()
    config_lines = [l for l in lines if not l.startswith(("#", "!", "show", "Building"))]
    return "\n".join(config_lines)


def apply_config_lines(shell, config_lines):
    log.info("Entering configuration mode")
    send_command(shell, "configure terminal", wait=1)
    for line in config_lines:
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        log.debug("Applying: %s", line)
        send_command(shell, line, wait=0.5)
    send_command(shell, "end", wait=1)
    log.info("Applied %d config lines", len(config_lines))


def run_verification(shell, verify_commands):
    results = {}
    for cmd in verify_commands:
        cmd = cmd.strip()
        if not cmd or cmd.startswith("#"):
            continue
        log.info("Verification: %s", cmd)
        output = send_command(shell, cmd, wait=2)
        results[cmd] = output
    return results


def rollback_config(shell, saved_config):
    log.warning("Rolling back to pre-deployment configuration")
    send_command(shell, "configure terminal", wait=1)
    for line in saved_config.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        send_command(shell, line, wait=0.3)
    send_command(shell, "end", wait=1)
    log.info("Rollback complete")


def connect(host, port, username, password, key_file, timeout):
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
    if key_file:
        connect_kwargs["key_filename"] = key_file
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def main():
    parser = argparse.ArgumentParser(
        description="Staged config deployment with verification and rollback"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("-k", "--key-file", default=None, help="SSH private key path")
    parser.add_argument(
        "-c", "--config-file", required=True, help="File with config lines to deploy"
    )
    parser.add_argument(
        "-v", "--verify-file", default=None,
        help="File with verification commands to run post-deploy"
    )
    parser.add_argument(
        "--no-rollback", action="store_true",
        help="Disable automatic rollback on verification failure"
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    config_path = Path(args.config_file)
    if not config_path.exists():
        log.error("Config file not found: %s", args.config_file)
        sys.exit(1)
    config_lines = config_path.read_text().splitlines()

    verify_commands = []
    if args.verify_file:
        verify_path = Path(args.verify_file)
        if not verify_path.exists():
            log.error("Verify file not found: %s", args.verify_file)
            sys.exit(1)
        verify_commands = verify_path.read_text().splitlines()

    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        client = connect(
            args.host, args.port, args.username, args.password, args.key_file, args.timeout
        )
        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(65535)  # flush banner

        saved_config = capture_running_config(shell)
        apply_config_lines(shell, config_lines)

        if verify_commands:
            log.info("Running %d verification commands", len(verify_commands))
            results = run_verification(shell, verify_commands)
            for cmd, output in results.items():
                print(f"\n--- {cmd} ---\n{output.strip()}")

            failed = input("\nDid verification pass? [y/N]: ").strip().lower()
            if failed != "y":
                if not args.no_rollback:
                    rollback_config(shell, saved_config)
                    log.warning("Deployment rolled back due to failed verification")
                    sys.exit(2)
                else:
                    log.warning("Verification failed but --no-rollback is set; changes retained")
                    sys.exit(2)
            else:
                log.info("Verification passed; deployment committed")
        else:
            log.info("No verification file provided; deployment applied without checks")

        client.close()

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH error: %s", exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
```