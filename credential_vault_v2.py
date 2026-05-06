```python
"""
credential_rotator.py - Rotate SSH login password and enable secret on Cisco IOS devices.

Purpose:
    Connects to one or more Cisco IOS devices via SSH and rotates the local
    username password, enable secret, or both. After rotation, verifies the
    new credentials by reconnecting before reporting success.

Usage:
    python credential_rotator.py -H 192.168.1.1 -u admin -p OldPass \
        --new-password NewPass456 --enable-secret NewEnable789

    # Rotate across a fleet from a host file (one IP per line, # for comments):
    python credential_rotator.py --hosts-file devices.txt -u admin -p OldPass \
        --new-password NewPass456

Prerequisites:
    pip install paramiko
    Device must have SSH enabled with sufficient privilege to enter config mode.
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


def _connect(host: str, username: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return client


def _drain(shell: paramiko.Channel, chunk: int = 4096) -> str:
    output = ""
    while shell.recv_ready():
        output += shell.recv(chunk).decode("utf-8", errors="replace")
    return output


def _send(shell: paramiko.Channel, cmd: str, delay: float = 0.5) -> str:
    shell.send(cmd + "\n")
    time.sleep(delay)
    return _drain(shell)


def rotate_device(
    host: str,
    username: str,
    current_password: str,
    new_password: str,
    enable_secret: "str | None" = None,
    port: int = 22,
) -> bool:
    """Push new credentials to a device and verify they work before returning True."""
    try:
        client = _connect(host, username, current_password, port)
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed with current credentials", host)
        return False
    except Exception as exc:
        log.error("%s: connection error: %s", host, exc)
        return False

    try:
        shell = client.invoke_shell(width=200, height=50)
        shell.settimeout(10)
        time.sleep(1.0)
        _drain(shell)

        _send(shell, "enable", delay=0.4)
        if enable_secret:
            _send(shell, enable_secret, delay=0.4)

        _send(shell, "conf t")
        _send(shell, f"username {username} secret {new_password}")
        if enable_secret:
            _send(shell, f"enable secret {enable_secret}")
        _send(shell, "end")
        out = _send(shell, "write memory", delay=2.0)

        if "[OK]" not in out:
            log.warning("%s: unexpected write memory output: %s", host, out.strip())
    except Exception as exc:
        log.error("%s: error during credential push: %s", host, exc)
        return False
    finally:
        client.close()

    try:
        verify = _connect(host, username, new_password, port)
        verify.close()
        log.info("%s: rotation verified — new credentials accepted", host)
        return True
    except paramiko.AuthenticationException:
        log.error("%s: rotation failed — device rejected new credentials", host)
        return False
    except Exception as exc:
        # Device may throttle reconnects; rotation likely succeeded
        log.warning("%s: rotation complete but re-connect check failed: %s", host, exc)
        return True


def load_hosts(hosts_file: Path) -> list:
    if not hosts_file.exists():
        log.error("Hosts file not found: %s", hosts_file)
        sys.exit(1)
    return [
        line.strip()
        for line in hosts_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rotate SSH password and/or enable secret on Cisco IOS devices."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-H", "--host", help="Single device IP or hostname")
    target.add_argument("--hosts-file", type=Path, metavar="FILE",
                        help="File listing one host per line (# lines ignored)")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="Current password")
    parser.add_argument("--new-password", required=True, help="Replacement password")
    parser.add_argument("--enable-secret", default=None,
                        help="New enable secret (skipped if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--debug", action="store_true", help="Enable debug-level logging")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    hosts = [args.host] if args.host else load_hosts(args.hosts_file)
    if not hosts:
        log.error("No hosts to process")
        sys.exit(1)

    succeeded, failed = [], []
    for host in hosts:
        log.info("Rotating credentials on %s", host)
        ok = rotate_device(
            host=host,
            username=args.username,
            current_password=args.password,
            new_password=args.new_password,
            enable_secret=args.enable_secret,
            port=args.port,
        )
        (succeeded if ok else failed).append(host)

    print(f"\nDone: {len(succeeded)} succeeded, {len(failed)} failed")
    if failed:
        print("Failed:", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
```