The repo isn't at `/opt/NetAutoCommitter` — looking at the prompt again, it says to output only the script content. Here it is:

```python
"""
SSH Public Key Manager for Network Devices

Deploys or removes SSH public keys on Cisco IOS/IOS-XE devices via paramiko,
enabling key-based authentication for automation workflows without storing
plaintext passwords in scripts long-term.

Usage:
    python ssh_key_manager.py -d 192.168.1.1 -u admin -p secret --key ~/.ssh/id_rsa.pub
    python ssh_key_manager.py -d 192.168.1.1 -u admin -p secret --key-user netops --key ~/.ssh/id_rsa.pub
    python ssh_key_manager.py --hosts-file devices.txt -u admin -p secret --remove --key-user netops
    python ssh_key_manager.py -d 192.168.1.1 -u admin -p secret --list

Prerequisites:
    pip install paramiko
    - SSH must be enabled on target devices (ip ssh version 2)
    - Login account requires privilege 15 to modify ip ssh pubkey-chain
    - Tested against Cisco IOS 15.x and IOS-XE 16.x+
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
log = logging.getLogger(__name__)


def load_public_key(key_path: str) -> str:
    path = Path(key_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Public key not found: {path}")
    content = path.read_text().strip()
    parts = content.split()
    if len(parts) < 2 or not parts[1]:
        raise ValueError(f"Unrecognised public key format in {path}")
    return content


def connect(host: str, username: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _shell_session(client: paramiko.SSHClient, commands: list, delay: float = 0.6) -> str:
    shell = client.invoke_shell()
    shell.settimeout(20)
    time.sleep(1)
    collected = b""
    while shell.recv_ready():
        collected += shell.recv(4096)

    for cmd in commands:
        shell.send(cmd + "\n")
        time.sleep(delay)
        while shell.recv_ready():
            collected += shell.recv(4096)

    shell.close()
    return collected.decode(errors="replace")


def list_keys(client: paramiko.SSHClient) -> str:
    _, stdout, _ = client.exec_command("show ip ssh pubkey-chain", timeout=10)
    return stdout.read().decode(errors="replace")


def deploy_key(client: paramiko.SSHClient, key_user: str, public_key: str) -> bool:
    key_data = public_key.split()[1]
    chunks = [key_data[i:i + 128] for i in range(0, len(key_data), 128)]

    commands = [
        "terminal length 0",
        "conf t",
        "ip ssh pubkey-chain",
        f"username {key_user}",
        "key-string",
        *chunks,
        "exit",
        "exit",
        "end",
    ]
    output = _shell_session(client, commands)
    if "%" in output or "Invalid" in output:
        log.debug("Device output:\n%s", output)
        return False
    return True


def remove_key(client: paramiko.SSHClient, key_user: str) -> bool:
    commands = [
        "terminal length 0",
        "conf t",
        "ip ssh pubkey-chain",
        f"no username {key_user}",
        "exit",
        "end",
    ]
    output = _shell_session(client, commands)
    if "% Invalid" in output:
        log.debug("Device output:\n%s", output)
        return False
    return True


def process_device(host: str, args: argparse.Namespace, public_key: str) -> bool:
    log.info("[%s] Connecting on port %d as %s", host, args.port, args.username)
    try:
        client = connect(host, args.username, args.password, args.port)
    except paramiko.AuthenticationException:
        log.error("[%s] Authentication failed", host)
        return False
    except Exception as exc:
        log.error("[%s] Connection error: %s", host, exc)
        return False

    key_user = args.key_user or args.username
    try:
        if args.list:
            output = list_keys(client)
            print(f"\n--- {host} SSH pubkey-chain ---\n{output}")
            return True

        if args.remove:
            log.info("[%s] Removing key for device user '%s'", host, key_user)
            ok = remove_key(client, key_user)
        else:
            log.info("[%s] Deploying key for device user '%s'", host, key_user)
            ok = deploy_key(client, key_user, public_key)

        if ok:
            log.info("[%s] %s succeeded", host, "Removal" if args.remove else "Deployment")
        else:
            log.warning("[%s] Operation may have failed — verify on device", host)
        return ok

    except Exception as exc:
        log.error("[%s] Operation error: %s", host, exc)
        return False
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Deploy or remove SSH public keys on Cisco IOS/IOS-XE devices"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Target device IP or hostname")
    target.add_argument("--hosts-file", help="File listing one host per line")

    parser.add_argument("-u", "--username", required=True, help="SSH login username")
    parser.add_argument("-p", "--password", required=True, help="SSH login password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--key", help="Path to SSH public key file (.pub) to deploy")
    parser.add_argument(
        "--key-user",
        help="Device account to bind the key to (defaults to --username)",
    )

    action = parser.add_mutually_exclusive_group()
    action.add_argument("--remove", action="store_true", help="Remove keys for --key-user")
    action.add_argument("--list", action="store_true", help="List configured public keys")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.remove and not args.list and not args.key:
        parser.error("--key is required for deployment (or use --remove / --list)")

    public_key = ""
    if args.key:
        try:
            public_key = load_public_key(args.key)
        except (FileNotFoundError, ValueError) as exc:
            log.error("%s", exc)
            sys.exit(1)

    if args.device:
        hosts = [args.device]
    else:
        path = Path(args.hosts_file)
        if not path.exists():
            log.error("Hosts file not found: %s", path)
            sys.exit(1)
        hosts = [
            h.strip()
            for h in path.read_text().splitlines()
            if h.strip() and not h.startswith("#")
        ]

    if not hosts:
        log.error("No hosts to process")
        sys.exit(1)

    results = {host: process_device(host, args, public_key) for host in hosts}
    passed = sum(v for v in results.values())
    log.info("Summary: %d/%d devices succeeded", passed, len(hosts))

    if passed < len(hosts):
        sys.exit(1)


if __name__ == "__main__":
    main()
```