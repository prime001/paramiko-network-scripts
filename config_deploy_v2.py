```python
"""
verified_config_deploy.py - Deploy configuration with pre/post state capture and auto-rollback.

Purpose:
    Push configuration commands to a network device, optionally capture pre/post
    state via show commands, and automatically roll back if the device becomes
    unreachable or SSH connectivity is lost after the change.

Usage:
    python verified_config_deploy.py -d 192.168.1.1 -u admin -p secret \\
        -c commands.txt [-v verify_cmds.txt] [-r rollback_cmds.txt] \\
        [--rollback-on-failure] [--save] [--state-output state.txt]

Prerequisites:
    pip install paramiko

File formats (all plain text, one entry per line, # lines ignored):
    commands.txt      - IOS/NX-OS config commands to apply
    verify_cmds.txt   - show commands run before and after (for comparison)
    rollback_cmds.txt - config commands to revert the change on failure
"""

import argparse
import logging
import socket
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=username, password=password,
        timeout=timeout, look_for_keys=False, allow_agent=False,
    )
    return client


def run_commands(client, commands, inter_cmd_delay=1.0):
    shell = client.invoke_shell(width=200, height=200)
    time.sleep(inter_cmd_delay)
    shell.recv(65535)

    parts = []
    for cmd in commands:
        shell.send(cmd + "\n")
        time.sleep(inter_cmd_delay)
        chunk = b""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if shell.recv_ready():
                chunk += shell.recv(65535)
            else:
                break
        parts.append(chunk.decode("utf-8", errors="replace"))

    shell.close()
    return "\n".join(parts)


def is_reachable(host, port, timeout=10):
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def load_lines(path):
    with open(path) as fh:
        return [l.strip() for l in fh if l.strip() and not l.startswith("#")]


def do_rollback(args):
    rollback_cmds = load_lines(args.rollback_file)
    logger.warning("Rolling back: pushing %d commands from %s", len(rollback_cmds), args.rollback_file)
    try:
        client = ssh_connect(args.device, args.username, args.password, args.port)
        run_commands(client, rollback_cmds)
        if args.save:
            run_commands(client, ["write memory"])
        client.close()
        logger.info("Rollback complete")
    except Exception as exc:
        logger.error("Rollback also failed: %s", exc)


def deploy(args):
    config_cmds = load_lines(args.commands_file)
    verify_cmds = load_lines(args.verify_file) if args.verify_file else []

    logger.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = ssh_connect(args.device, args.username, args.password, args.port)
    except Exception as exc:
        logger.error("Pre-deploy connection failed: %s", exc)
        sys.exit(1)

    pre_state = ""
    if verify_cmds:
        logger.info("Collecting pre-deploy state (%d commands)", len(verify_cmds))
        pre_state = run_commands(client, verify_cmds)

    logger.info("Deploying %d configuration commands", len(config_cmds))
    deploy_out = run_commands(client, config_cmds)
    logger.debug("Deploy output:\n%s", deploy_out)

    if args.save:
        logger.info("Saving configuration")
        run_commands(client, ["write memory"])

    client.close()

    logger.info("Waiting %ds before post-deploy verification", args.settle_time)
    time.sleep(args.settle_time)

    if not is_reachable(args.device, args.port):
        logger.error("Device unreachable after deploy — connectivity lost")
        if args.rollback_on_failure and args.rollback_file:
            do_rollback(args)
        sys.exit(2)

    post_state = ""
    if verify_cmds:
        logger.info("Collecting post-deploy state")
        try:
            post_client = ssh_connect(args.device, args.username, args.password, args.port)
            post_state = run_commands(post_client, verify_cmds)
            post_client.close()
        except Exception as exc:
            logger.error("Post-deploy connection failed: %s", exc)
            if args.rollback_on_failure and args.rollback_file:
                do_rollback(args)
            sys.exit(2)

    if args.state_output and verify_cmds:
        with open(args.state_output, "w") as fh:
            fh.write("=== PRE-DEPLOY STATE ===\n")
            fh.write(pre_state)
            fh.write("\n=== POST-DEPLOY STATE ===\n")
            fh.write(post_state)
        logger.info("State comparison written to %s", args.state_output)

    logger.info("Deployment verified successfully on %s", args.device)


def main():
    parser = argparse.ArgumentParser(
        description="Deploy network config with pre/post verification and optional rollback"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-c", "--commands-file", required=True,
                        help="File containing config commands (one per line)")
    parser.add_argument("-v", "--verify-file",
                        help="File with show commands for pre/post state capture")
    parser.add_argument("-r", "--rollback-file",
                        help="File with rollback commands to push on failure")
    parser.add_argument("--rollback-on-failure", action="store_true",
                        help="Automatically push rollback commands if post-check fails")
    parser.add_argument("--save", action="store_true",
                        help="Run 'write memory' after deploying")
    parser.add_argument("--settle-time", type=int, default=5,
                        help="Seconds to wait before post-deploy check (default: 5)")
    parser.add_argument("--state-output",
                        help="File to write pre/post state comparison")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.rollback_on_failure and not args.rollback_file:
        parser.error("--rollback-on-failure requires --rollback-file")

    deploy(args)


if __name__ == "__main__":
    main()
```