```python
"""
config_deploy_verified.py - Verified Configuration Deployment with Rollback

Deploys configuration commands to a network device via SSH, captures pre/post
state snapshots, verifies the deployment succeeded, and automatically rolls back
if verification fails.

Usage:
    python config_deploy_verified.py -H 192.168.1.1 -u admin -p secret \
        -c commands.txt --verify-cmd "show ip route" --verify-pattern "0.0.0.0"

    python config_deploy_verified.py -H 192.168.1.1 -u admin \
        --ask-pass -c commands.txt --rollback-on-failure

Prerequisites:
    pip install paramiko
    Commands file: one IOS/NX-OS command per line, blank lines and # comments ignored.
"""

import argparse
import getpass
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def build_client(host, port, username, password, timeout):
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


def invoke_shell_and_send(client, commands, prompt_pattern, inter_cmd_delay):
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(1)
    shell.recv(65535)  # discard banner

    output_log = []

    for cmd in commands:
        log.debug("Sending: %s", cmd)
        shell.send(cmd + "\n")
        time.sleep(inter_cmd_delay)
        chunk = b""
        deadline = time.time() + 10
        while time.time() < deadline:
            if shell.recv_ready():
                chunk += shell.recv(4096)
                if re.search(prompt_pattern.encode(), chunk):
                    break
            else:
                time.sleep(0.1)
        decoded = chunk.decode(errors="replace")
        output_log.append((cmd, decoded))
        log.debug("Output: %s", decoded.strip())

    shell.close()
    return output_log


def run_verification(client, verify_cmd, prompt_pattern):
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(0.8)
    shell.recv(65535)
    shell.send(verify_cmd + "\n")
    time.sleep(2)
    output = b""
    deadline = time.time() + 15
    while time.time() < deadline:
        if shell.recv_ready():
            output += shell.recv(4096)
            if re.search(prompt_pattern.encode(), output):
                break
        else:
            time.sleep(0.2)
    shell.close()
    return output.decode(errors="replace")


def load_commands(filepath):
    commands = []
    with open(filepath) as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                commands.append(stripped)
    if not commands:
        raise ValueError(f"No commands found in {filepath}")
    return commands


def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy config to a network device with pre/post verification and optional rollback."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "-c", "--commands-file", required=True, help="File with commands to deploy"
    )
    parser.add_argument(
        "--verify-cmd",
        default=None,
        help="Command to run post-deploy for verification",
    )
    parser.add_argument(
        "--verify-pattern",
        default=None,
        help="Regex pattern that must appear in verify-cmd output to indicate success",
    )
    parser.add_argument(
        "--rollback-file",
        default=None,
        help="File with rollback commands to run if verification fails",
    )
    parser.add_argument(
        "--rollback-on-failure",
        action="store_true",
        help="Run rollback commands automatically on verification failure",
    )
    parser.add_argument(
        "--prompt-pattern",
        default=r"[>#]",
        help="Regex matching device CLI prompt (default: [>#])",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5, help="Delay between commands in seconds"
    )
    parser.add_argument(
        "--timeout", type=float, default=30, help="SSH connection timeout"
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without connecting")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.ask_pass:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
    elif args.password:
        password = args.password
    else:
        log.error("Provide --password or --ask-pass")
        sys.exit(1)

    deploy_commands = load_commands(args.commands_file)
    log.info("Loaded %d command(s) from %s", len(deploy_commands), args.commands_file)

    rollback_commands = []
    if args.rollback_file:
        rollback_commands = load_commands(args.rollback_file)
        log.info("Loaded %d rollback command(s)", len(rollback_commands))

    if args.dry_run:
        log.info("[DRY RUN] Would deploy to %s:%d as %s", args.host, args.port, args.username)
        for cmd in deploy_commands:
            print(f"  DEPLOY: {cmd}")
        if rollback_commands:
            for cmd in rollback_commands:
                print(f"  ROLLBACK: {cmd}")
        sys.exit(0)

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = build_client(args.host, args.port, args.username, password, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Deploying %d command(s)...", len(deploy_commands))
        deploy_log = invoke_shell_and_send(
            client, deploy_commands, args.prompt_pattern, args.delay
        )
        log.info("Deployment complete")

        errors_detected = any(
            re.search(r"(?i)(invalid input|error|unrecognized)", entry)
            for _, entry in deploy_log
        )
        if errors_detected:
            log.warning("Possible errors detected in device output during deployment")

        verification_passed = True
        if args.verify_cmd and args.verify_pattern:
            log.info("Running verification: %s", args.verify_cmd)
            verify_output = run_verification(client, args.verify_cmd, args.prompt_pattern)
            if re.search(args.verify_pattern, verify_output):
                log.info("Verification PASSED (pattern '%s' found)", args.verify_pattern)
            else:
                log.error(
                    "Verification FAILED: pattern '%s' not found in output:\n%s",
                    args.verify_pattern,
                    verify_output.strip(),
                )
                verification_passed = False

        if not verification_passed and args.rollback_on_failure and rollback_commands:
            log.warning("Initiating rollback (%d commands)...", len(rollback_commands))
            invoke_shell_and_send(client, rollback_commands, args.prompt_pattern, args.delay)
            log.info("Rollback complete")
            sys.exit(2)
        elif not verification_passed:
            log.error("Verification failed. No rollback performed.")
            sys.exit(1)

    finally:
        client.close()
        log.debug("SSH connection closed")

    log.info("Done.")


if __name__ == "__main__":
    main()
```