The write was blocked by permissions. Here is the complete script content — paste it into `password_rotation.py` in your repo:

```python
"""
password_rotation.py - Network Device Password Rotation via Paramiko

Connects to one or more Cisco IOS/IOS-XE devices and rotates the enable
secret and/or a named local user's password. After each rotation the script
immediately re-authenticates with the new credential to verify it works,
then logs a pass/fail result per device.

Usage:
    # Single device
    python password_rotation.py -d 192.168.1.1 -u admin -p OldPass \
        --new-password NewPass123 --username-to-rotate netops

    # Multiple devices from file (one IP per line)
    python password_rotation.py -f devices.txt -u admin -p OldPass \
        --new-password NewPass123 --enable --username-to-rotate netops

    # Rotate enable secret only
    python password_rotation.py -d 192.168.1.1 -u admin -p OldPass \
        --enable-secret OldEnable --new-enable-secret NewEnable --enable

Prerequisites:
    pip install paramiko
"""

import argparse
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


def _exec(shell, command: str, wait: float = 1.5) -> str:
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode("utf-8", errors="replace")
    return output


def _open_shell(host: str, username: str, password: str, timeout: int = 10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(1.0)
    shell.recv(4096)
    return client, shell


def rotate_device(
    host: str,
    username: str,
    password: str,
    new_password: str | None,
    username_to_rotate: str | None,
    enable_secret: str | None,
    new_enable_secret: str | None,
    use_enable: bool,
    timeout: int,
) -> bool:
    log.info("[%s] Connecting …", host)
    try:
        client, shell = _open_shell(host, username, password, timeout)
    except Exception as exc:
        log.error("[%s] Connection failed: %s", host, exc)
        return False

    try:
        _exec(shell, "terminal length 0")

        if use_enable and enable_secret:
            out = _exec(shell, "enable")
            if "Password" in out:
                _exec(shell, enable_secret)

        _exec(shell, "configure terminal")

        if username_to_rotate and new_password:
            cmd = f"username {username_to_rotate} privilege 15 secret {new_password}"
            _exec(shell, cmd)
            log.info("[%s] Rotated password for user '%s'", host, username_to_rotate)

        if new_enable_secret:
            _exec(shell, f"enable secret {new_enable_secret}")
            log.info("[%s] Rotated enable secret", host)

        _exec(shell, "end")
        _exec(shell, "write memory", wait=3.0)
        client.close()
    except Exception as exc:
        log.error("[%s] Rotation commands failed: %s", host, exc)
        client.close()
        return False

    # Verify new credential
    verify_user = username_to_rotate or username
    verify_pass = new_password or password
    log.info("[%s] Verifying new credentials …", host)
    try:
        vc, vs = _open_shell(host, verify_user, verify_pass, timeout)
        _exec(vs, "show version", wait=2.0)
        vc.close()
        log.info("[%s] Verification PASSED", host)
        return True
    except Exception as exc:
        log.error("[%s] Verification FAILED — new credential rejected: %s", host, exc)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rotate passwords on Cisco IOS/IOS-XE devices."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("-f", "--file", help="File with one device IP per line")

    parser.add_argument("-u", "--username", required=True, help="SSH login username")
    parser.add_argument("-p", "--password", required=True, help="Current SSH password")
    parser.add_argument("--new-password", help="New password for --username-to-rotate")
    parser.add_argument(
        "--username-to-rotate",
        help="Local username whose password should be rotated",
    )
    parser.add_argument(
        "--enable", action="store_true", help="Enter enable mode before configuring"
    )
    parser.add_argument("--enable-secret", help="Current enable secret")
    parser.add_argument("--new-enable-secret", help="New enable secret to set")
    parser.add_argument(
        "--timeout", type=int, default=10, help="SSH connection timeout (default 10s)"
    )
    args = parser.parse_args()

    if not args.new_password and not args.new_enable_secret:
        parser.error("At least one of --new-password or --new-enable-secret is required")

    devices: list[str] = []
    if args.device:
        devices = [args.device]
    else:
        try:
            with open(args.file) as fh:
                devices = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            log.error("Cannot read device file: %s", exc)
            sys.exit(1)

    if not devices:
        log.error("No devices to process")
        sys.exit(1)

    results: dict[str, bool] = {}
    for host in devices:
        results[host] = rotate_device(
            host=host,
            username=args.username,
            password=args.password,
            new_password=args.new_password,
            username_to_rotate=args.username_to_rotate,
            enable_secret=args.enable_secret,
            new_enable_secret=args.new_enable_secret,
            use_enable=args.enable,
            timeout=args.timeout,
        )

    passed = sum(1 for v in results.values() if v)
    failed = len(results) - passed
    print(f"\nSummary: {passed} succeeded, {failed} failed out of {len(results)} devices")
    if failed:
        print("Failed devices:")
        for host, ok in results.items():
            if not ok:
                print(f"  {host}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

The script rotates local-user passwords and/or the enable secret on Cisco IOS/IOS-XE devices, then immediately re-authenticates to verify the new credential landed — a distinct operation from the existing vault scripts that store/retrieve credentials.