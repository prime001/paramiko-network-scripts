```python
"""
SSH Public Key Deployer for Network Devices

Deploys an SSH public key to Cisco IOS/IOS-XE devices using the
ip ssh pubkey-chain mechanism, enabling key-based authentication for
automation accounts and eliminating password prompts in pipelines.

Usage:
    python ssh_key_deployer.py -H 192.168.1.1 -u admin -p secret --key ~/.ssh/id_rsa.pub
    python ssh_key_deployer.py -H hosts.txt -u netops -p secret --key ~/.ssh/id_rsa.pub --verify

Prerequisites:
    - pip install paramiko
    - IOS 15.2+ or IOS-XE (ip ssh pubkey-chain support)
    - SSH v2 enabled: ip ssh version 2
    - Deploying account needs privilege 15 or config access
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
logger = logging.getLogger(__name__)

# IOS limits key-string lines to 254 characters
_IOS_KEY_CHUNK = 254


def _recv_until_stable(shell, pause=1.5):
    time.sleep(pause)
    buf = b""
    while shell.recv_ready():
        buf += shell.recv(8192)
        time.sleep(0.1)
    return buf.decode("utf-8", errors="ignore")


def _send(shell, cmd, pause=0.6):
    shell.send(cmd + "\n")
    return _recv_until_stable(shell, pause)


def deploy_key_to_device(host, port, username, password, public_key, timeout):
    parts = public_key.strip().split()
    if len(parts) < 2 or not parts[0].startswith("ssh-"):
        raise ValueError("Not a valid SSH public key")
    key_data = parts[1]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell(width=200, height=200)
        _recv_until_stable(shell, pause=2)

        _send(shell, "terminal length 0")
        _send(shell, "configure terminal")
        _send(shell, "ip ssh pubkey-chain")
        _send(shell, f"username {username}")
        _send(shell, "key-string")

        chunks = [key_data[i:i + _IOS_KEY_CHUNK] for i in range(0, len(key_data), _IOS_KEY_CHUNK)]
        for chunk in chunks:
            _send(shell, chunk, pause=0.3)

        _send(shell, "exit")   # exit key-string
        _send(shell, "exit")   # exit username
        _send(shell, "exit")   # exit pubkey-chain
        out = _send(shell, "end")

        verify = _send(shell, "show running-config | section ip ssh pubkey", pause=2)
        deployed = key_data[:32] in verify
        return deployed, verify

    except paramiko.AuthenticationException:
        raise RuntimeError("Authentication failed — check credentials")
    except paramiko.SSHException as exc:
        raise RuntimeError(f"SSH negotiation error: {exc}")
    finally:
        client.close()


def verify_key_present(host, port, username, password, public_key, timeout):
    parts = public_key.strip().split()
    key_data = parts[1] if len(parts) >= 2 else ""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
        )
        shell = client.invoke_shell(width=200)
        _recv_until_stable(shell, pause=2)
        _send(shell, "terminal length 0")
        out = _send(shell, "show running-config | section ip ssh pubkey", pause=2)
        return key_data[:32] in out
    finally:
        client.close()


def load_hosts(source):
    p = Path(source).expanduser()
    if p.exists():
        return [l.strip() for l in p.read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    return [source]


def main():
    parser = argparse.ArgumentParser(
        description="Deploy SSH public key to Cisco IOS/IOS-XE network devices"
    )
    parser.add_argument("-H", "--host", required=True,
                        help="Device IP/hostname, or path to file with one host per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--key", required=True,
                        help="Path to SSH public key file (e.g. ~/.ssh/id_rsa.pub)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    parser.add_argument("--verify", action="store_true",
                        help="Only verify if key is present; do not deploy")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would happen without connecting")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show device output")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    key_path = Path(args.key).expanduser()
    if not key_path.exists():
        logger.error("Key file not found: %s", key_path)
        sys.exit(1)
    public_key = key_path.read_text().strip()
    if not public_key.split()[0].startswith("ssh-"):
        logger.error("Not a valid SSH public key: %s", key_path)
        sys.exit(1)

    hosts = load_hosts(args.host)
    action = "Verifying" if args.verify else "Deploying"
    logger.info("%s key on %d host(s)", action, len(hosts))

    if args.dry_run:
        for h in hosts:
            print(f"[DRY-RUN] Would {'verify' if args.verify else 'deploy'} key on {h}")
        sys.exit(0)

    ok_hosts, fail_hosts = [], []

    for host in hosts:
        try:
            if args.verify:
                present = verify_key_present(host, args.port, args.username,
                                             args.password, public_key, args.timeout)
                status = "KEY PRESENT" if present else "KEY MISSING"
                logger.info("[%s] %s", status, host)
                (ok_hosts if present else fail_hosts).append(host)
            else:
                deployed, detail = deploy_key_to_device(
                    host, args.port, args.username, args.password, public_key, args.timeout
                )
                if deployed:
                    logger.info("[OK] %s — key confirmed in running-config", host)
                    ok_hosts.append(host)
                else:
                    logger.warning("[WARN] %s — deploy completed but key not found in config", host)
                    fail_hosts.append(host)
                if args.verbose:
                    logger.debug("Device output:\n%s", detail)
        except Exception as exc:
            logger.error("[FAIL] %s — %s", host, exc)
            fail_hosts.append(host)

    print(f"\n{'─' * 40}")
    print(f"Result: {len(ok_hosts)} OK / {len(fail_hosts)} failed / {len(hosts)} total")
    for h in ok_hosts:
        print(f"  ✓  {h}")
    for h in fail_hosts:
        print(f"  ✗  {h}")

    sys.exit(1 if fail_hosts else 0)


if __name__ == "__main__":
    main()
```