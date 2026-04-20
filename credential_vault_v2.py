```python
"""
ssh_key_deployer.py - Deploy SSH public keys to network devices for key-based authentication.

Purpose:
    Automates the deployment of SSH public keys to Cisco IOS/IOS-XE/NX-OS devices,
    enabling passwordless authentication. Reads an existing public key file and
    configures it on target devices via paramiko using initial password auth.

Usage:
    python ssh_key_deployer.py -d 192.168.1.1 -u admin -p secret --key ~/.ssh/id_rsa.pub
    python ssh_key_deployer.py --hosts hosts.txt -u admin --key ~/.ssh/id_rsa.pub --verify
    python ssh_key_deployer.py -d 10.0.0.1 -u admin -p secret --key ~/.ssh/id_rsa.pub --dry-run

Prerequisites:
    - pip install paramiko
    - SSH access to target devices with password authentication enabled
    - Devices must support crypto key import (IOS 12.3+, NX-OS 5.x+)
    - RSA or ECDSA public key in OpenSSH format
"""

import argparse
import base64
import logging
import sys
import time
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def load_public_key(key_path: str) -> tuple[str, str]:
    path = Path(key_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Public key not found: {path}")
    raw = path.read_text().strip()
    parts = raw.split()
    if len(parts) < 2:
        raise ValueError(f"Invalid public key format in {path}")
    key_type, key_data = parts[0], parts[1]
    return key_type, key_data


def connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def send_command(shell, command: str, wait: float = 1.5) -> str:
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode("utf-8", errors="replace")
    return output


def deploy_key_ios(shell, username: str, key_type: str, key_data: str, dry_run: bool) -> bool:
    label = f"{username}-pubkey"
    commands = [
        f"ip ssh pubkey-chain",
        f"username {username}",
        f"key-string",
    ]
    chunk_size = 72
    key_chunks = [key_data[i:i + chunk_size] for i in range(0, len(key_data), chunk_size)]
    commands.extend(key_chunks)
    commands.extend(["exit", "exit", "exit"])

    if dry_run:
        log.info("[DRY-RUN] Would send %d config lines for key label '%s'", len(commands), label)
        return True

    send_command(shell, "conf t", wait=0.5)
    for cmd in commands:
        out = send_command(shell, cmd, wait=0.3)
        if "Invalid" in out or "Error" in out:
            log.error("Device rejected command '%s': %s", cmd.strip(), out.strip())
            send_command(shell, "end", wait=0.5)
            return False

    send_command(shell, "end", wait=0.5)
    return True


def verify_key_ios(shell, username: str) -> bool:
    out = send_command(shell, f"show ip ssh", wait=1.0)
    out += send_command(shell, f"show run | section ip ssh pubkey-chain", wait=1.5)
    return username in out


def deploy_to_device(
    host: str,
    username: str,
    password: str,
    key_type: str,
    key_data: str,
    port: int = 22,
    dry_run: bool = False,
    verify: bool = False,
) -> dict:
    result = {"host": host, "status": "unknown", "message": ""}

    try:
        log.info("Connecting to %s:%d", host, port)
        client = connect(host, username, password, port)
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(1.0)
        shell.recv(4096)

        deployed = deploy_key_ios(shell, username, key_type, key_data, dry_run)

        if not deployed:
            result["status"] = "failed"
            result["message"] = "Key deployment commands rejected by device"
        elif dry_run:
            result["status"] = "dry-run"
            result["message"] = "Dry run completed, no changes made"
        elif verify:
            confirmed = verify_key_ios(shell, username)
            result["status"] = "verified" if confirmed else "unverified"
            result["message"] = (
                "Key confirmed in running config"
                if confirmed
                else "Could not confirm key in running config"
            )
        else:
            result["status"] = "deployed"
            result["message"] = "Key deployment commands sent successfully"

        client.close()

    except paramiko.AuthenticationException:
        result["status"] = "auth-failed"
        result["message"] = "Authentication failed — check credentials"
    except paramiko.SSHException as exc:
        result["status"] = "ssh-error"
        result["message"] = str(exc)
    except OSError as exc:
        result["status"] = "unreachable"
        result["message"] = str(exc)

    icon = {"deployed": "OK", "verified": "OK", "dry-run": "--"}.get(result["status"], "FAIL")
    log.info("[%s] %s — %s: %s", icon, host, result["status"], result["message"])
    return result


def parse_hosts_file(path: str) -> list[str]:
    lines = Path(path).read_text().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def main():
    parser = argparse.ArgumentParser(
        description="Deploy SSH public keys to network devices"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--device", help="Single device IP or hostname")
    group.add_argument("--hosts", metavar="FILE", help="File with one host per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", required=True, metavar="PUB_KEY", help="Path to public key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--verify", action="store_true", help="Verify key appears in running config")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without applying")
    parser.add_argument("--debug", action="store_true", help="Enable paramiko debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if args.password is None:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}: ")

    try:
        key_type, key_data = load_public_key(args.key)
        log.info("Loaded %s public key from %s", key_type, args.key)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)

    hosts = [args.device] if args.device else parse_hosts_file(args.hosts)
    if not hosts:
        log.error("No hosts to process")
        sys.exit(1)

    results = []
    for host in hosts:
        r = deploy_to_device(
            host=host,
            username=args.username,
            password=args.password,
            key_type=key_type,
            key_data=key_data,
            port=args.port,
            dry_run=args.dry_run,
            verify=args.verify,
        )
        results.append(r)

    ok = sum(1 for r in results if r["status"] in ("deployed", "verified", "dry-run"))
    fail = len(results) - ok
    log.info("Summary: %d/%d succeeded, %d failed", ok, len(results), fail)
    sys.exit(0 if fail == 0 else 1)


if __name__ == "__main__":
    main()
```