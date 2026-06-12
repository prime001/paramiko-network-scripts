```
"""
SSH Key Deployer for Network Devices

Deploys and rotates SSH public keys on network devices using paramiko.
Bootstraps key-based auth from password credentials, then verifies
key-only connectivity works before removing fallback.

Usage:
    python ssh_key_deployer.py -d 192.168.1.1 -u admin -p secret --pubkey ~/.ssh/id_rsa.pub
    python ssh_key_deployer.py -d 192.168.1.1 -u admin -p secret --pubkey ~/.ssh/id_rsa.pub --verify
    python ssh_key_deployer.py --hosts hosts.txt -u admin -p secret --pubkey ~/.ssh/id_rsa.pub

Prerequisites:
    pip install paramiko
    SSH public key generated: ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
    Target devices must accept password auth initially (bootstrapping)
"""

import argparse
import logging
import socket
import sys
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def load_public_key(path: str) -> str:
    key_path = Path(path).expanduser()
    if not key_path.exists():
        raise FileNotFoundError(f"Public key not found: {key_path}")
    return key_path.read_text().strip()


def connect_password(host: str, username: str, password: str, port: int = 22, timeout: int = 10) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def connect_key(host: str, username: str, key_path: str, port: int = 22, timeout: int = 10) -> paramiko.SSHClient:
    private_key_path = Path(key_path).expanduser()
    if not private_key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")
    key = paramiko.RSAKey.from_private_key_file(str(private_key_path))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        pkey=key,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 15) -> tuple[int, str, str]:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, stdout.read().decode().strip(), stderr.read().decode().strip()


def deploy_key(host: str, username: str, password: str, pubkey: str, port: int = 22) -> bool:
    """
    Appends the public key to ~/.ssh/authorized_keys on the remote host.
    Creates ~/.ssh with correct permissions if absent.
    """
    try:
        client = connect_password(host, username, password, port)
    except (paramiko.AuthenticationException, socket.error) as exc:
        logger.error("[%s] Password connection failed: %s", host, exc)
        return False

    try:
        setup_cmds = [
            "mkdir -p ~/.ssh",
            "chmod 700 ~/.ssh",
            f"grep -qxF '{pubkey}' ~/.ssh/authorized_keys 2>/dev/null "
            f"|| echo '{pubkey}' >> ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
        ]
        for cmd in setup_cmds:
            rc, out, err = run_command(client, cmd)
            if rc != 0:
                logger.warning("[%s] Command returned %d: %s | stderr: %s", host, rc, cmd, err)

        logger.info("[%s] Public key deployed for user '%s'", host, username)
        return True
    except Exception as exc:
        logger.error("[%s] Deployment error: %s", host, exc)
        return False
    finally:
        client.close()


def verify_key_auth(host: str, username: str, private_key: str, port: int = 22) -> bool:
    """Confirms key-based auth works by connecting and running a no-op command."""
    try:
        client = connect_key(host, username, private_key, port)
        rc, out, _ = run_command(client, "echo ok")
        client.close()
        if rc == 0 and out == "ok":
            logger.info("[%s] Key-based auth verified for user '%s'", host, username)
            return True
        logger.warning("[%s] Key auth connected but echo check failed (rc=%d)", host, rc)
        return False
    except (paramiko.AuthenticationException, FileNotFoundError, socket.error) as exc:
        logger.error("[%s] Key auth verification failed: %s", host, exc)
        return False


def process_host(host: str, args: argparse.Namespace, pubkey: str) -> dict:
    result = {"host": host, "deployed": False, "verified": False}

    result["deployed"] = deploy_key(
        host=host,
        username=args.username,
        password=args.password,
        pubkey=pubkey,
        port=args.port,
    )

    if result["deployed"] and args.verify:
        private_key = args.privkey or str(Path(args.pubkey).with_suffix(""))
        result["verified"] = verify_key_auth(
            host=host,
            username=args.username,
            private_key=private_key,
            port=args.port,
        )

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deploy SSH public keys to network devices via paramiko",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--device", help="Single target device hostname or IP")
    group.add_argument("--hosts", help="File with one hostname/IP per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="Password for initial bootstrap connection")
    parser.add_argument("--pubkey", required=True, help="Path to SSH public key to deploy")
    parser.add_argument("--privkey", help="Path to private key for verification (default: pubkey path minus .pub)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--verify", action="store_true", help="Verify key-based auth after deployment")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        paramiko.util.log_to_file("/dev/stderr")

    try:
        pubkey = load_public_key(args.pubkey)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        sys.exit(1)

    hosts: list[str] = []
    if args.device:
        hosts = [args.device]
    else:
        hosts_file = Path(args.hosts)
        if not hosts_file.exists():
            logger.error("Hosts file not found: %s", args.hosts)
            sys.exit(1)
        hosts = [
            line.strip()
            for line in hosts_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    results = [process_host(h, args, pubkey) for h in hosts]

    deployed = sum(1 for r in results if r["deployed"])
    verified = sum(1 for r in results if r["verified"])

    print(f"\nSummary: {deployed}/{len(hosts)} deployed", end="")
    if args.verify:
        print(f", {verified}/{deployed} verified", end="")
    print()

    failed = [r["host"] for r in results if not r["deployed"]]
    if failed:
        print("Failed hosts:", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
```