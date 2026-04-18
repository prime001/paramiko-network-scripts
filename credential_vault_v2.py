```python
#!/usr/bin/env python3
"""
SSH Key Deployment Tool for Network Devices

Purpose:
    Deploys SSH public keys to network devices to enable key-based
    authentication, reducing reliance on password-based logins.
    Connects initially via password auth, then installs the provided
    public key into the device's authorized keys or local key store.

Usage:
    python ssh_key_deploy.py -d 192.168.1.1 -u admin -p secret \
        -k ~/.ssh/id_rsa.pub --device-type ios

    python ssh_key_deploy.py -d 192.168.1.1 -u admin \
        --ask-pass -k ~/.ssh/id_rsa.pub --verify

Prerequisites:
    - pip install paramiko
    - SSH access to target device with password credentials
    - A generated RSA/ECDSA public key (ssh-keygen)
    - Device must support SSH key authentication (IOS 15.4+, EOS, NX-OS)
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

DEPLOY_COMMANDS = {
    "ios": [
        "ip ssh pubkey-chain",
        "username {username}",
        "key-string",
        "{key_body}",
        "exit",
        "exit",
    ],
    "eos": [
        "enable",
        "configure terminal",
        "management ssh",
        "no shutdown",
        "exit",
    ],
    "nxos": [
        "configure terminal",
        "username {username} sshkey {pub_key}",
        "end",
        "copy running-config startup-config",
    ],
    "linux": [],
}


def load_public_key(path: str) -> str:
    try:
        with open(path, "r") as f:
            key_data = f.read().strip()
        if not key_data.startswith(("ssh-rsa", "ssh-ed25519", "ecdsa-sha2")):
            raise ValueError("File does not appear to be a valid SSH public key")
        return key_data
    except FileNotFoundError:
        log.error("Public key file not found: %s", path)
        sys.exit(1)
    except ValueError as exc:
        log.error("Invalid public key: %s", exc)
        sys.exit(1)


def connect(host: str, port: int, username: str, password: str,
            timeout: int = 15) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        log.info("Connected to %s:%d as %s", host, port, username)
        return client
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except paramiko.SSHException as exc:
        log.error("SSH negotiation failed: %s", exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Connection to %s failed: %s", host, exc)
        sys.exit(1)


def run_interactive(client: paramiko.SSHClient, commands: list,
                    prompt_timeout: float = 3.0) -> str:
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(1.0)
    shell.recv(65535)

    output_parts = []
    for cmd in commands:
        shell.send(cmd + "\n")
        time.sleep(prompt_timeout)
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output_parts.append(chunk)

    shell.close()
    return "\n".join(output_parts)


def deploy_ios(client: paramiko.SSHClient, username: str, pub_key: str) -> bool:
    key_type, key_body = pub_key.split(" ", 2)[:2]
    chunk_size = 72
    key_chunks = [key_body[i:i + chunk_size]
                  for i in range(0, len(key_body), chunk_size)]

    commands = ["ip ssh pubkey-chain", f"username {username}", "key-string"]
    commands.extend(key_chunks)
    commands.extend(["exit", "exit", "end", "write memory"])

    log.info("Deploying SSH public key for user '%s' (IOS mode)", username)
    output = run_interactive(client, commands, prompt_timeout=2.0)
    log.debug("Device output:\n%s", output)

    if "Invalid" in output or "Error" in output:
        log.error("Device reported an error during key deployment")
        return False
    return True


def deploy_nxos(client: paramiko.SSHClient, username: str, pub_key: str) -> bool:
    commands = [
        "configure terminal",
        f"username {username} sshkey {pub_key}",
        "end",
        "copy running-config startup-config",
    ]
    log.info("Deploying SSH public key for user '%s' (NX-OS mode)", username)
    output = run_interactive(client, commands, prompt_timeout=3.0)
    log.debug("Device output:\n%s", output)
    return "Error" not in output


def deploy_linux(client: paramiko.SSHClient, pub_key: str) -> bool:
    setup_cmds = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    )
    inject_cmd = f"echo '{pub_key}' >> ~/.ssh/authorized_keys"
    dedup_cmd = "sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys"

    for cmd in (setup_cmds, inject_cmd, dedup_cmd):
        stdin, stdout, stderr = client.exec_command(cmd)
        exit_code = stdout.channel.recv_exit_status()
        err = stderr.read().decode().strip()
        if exit_code != 0:
            log.error("Command failed (exit %d): %s — %s", exit_code, cmd, err)
            return False
    log.info("SSH public key appended to ~/.ssh/authorized_keys")
    return True


def verify_key_auth(host: str, port: int, username: str,
                    key_path: str) -> bool:
    private_key_path = key_path.replace(".pub", "")
    try:
        pkey = paramiko.RSAKey.from_private_key_file(private_key_path)
    except (paramiko.SSHException, FileNotFoundError):
        try:
            pkey = paramiko.Ed25519Key.from_private_key_file(private_key_path)
        except Exception:
            log.warning("Could not load private key for verification; skipping")
            return False

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username=username,
                       pkey=pkey, timeout=10, allow_agent=False,
                       look_for_keys=False)
        client.close()
        log.info("Verification successful — key-based auth works for %s@%s",
                 username, host)
        return True
    except paramiko.AuthenticationException:
        log.error("Verification failed — key auth not accepted by device")
        return False
    except Exception as exc:
        log.warning("Verification connection error: %s", exc)
        return False


def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy SSH public keys to network devices"
    )
    parser.add_argument("-d", "--device", required=True,
                        help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True,
                        help="Login username")
    parser.add_argument("-p", "--password", default=None,
                        help="Login password (prompted if omitted)")
    parser.add_argument("--ask-pass", action="store_true",
                        help="Prompt for password interactively")
    parser.add_argument("-k", "--key-file", required=True,
                        help="Path to SSH public key file (.pub)")
    parser.add_argument("--device-type",
                        choices=["ios", "nxos", "linux"],
                        default="ios",
                        help="Target device OS type (default: ios)")
    parser.add_argument("--port", type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("--verify", action="store_true",
                        help="Verify key auth works after deployment")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or not password:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    pub_key = load_public_key(args.key_file)
    log.info("Loaded public key from %s", args.key_file)

    client = connect(args.device, args.port, args.username, password)

    try:
        if args.device_type == "ios":
            success = deploy_ios(client, args.username, pub_key)
        elif args.device_type == "nxos":
            success = deploy_nxos(client, args.username, pub_key)
        elif args.device_type == "linux":
            success = deploy_linux(client, pub_key)
        else:
            log.error("Unsupported device type: %s", args.device_type)
            sys.exit(1)
    finally:
        client.close()

    if not success:
        log.error("Key deployment failed")
        sys.exit(1)

    log.info("SSH public key deployed successfully to %s", args.device)

    if args.verify:
        verified = verify_key_auth(args.device, args.port,
                                   args.username, args.key_file)
        sys.exit(0 if verified else 1)
```