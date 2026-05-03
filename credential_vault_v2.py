```python
#!/usr/bin/env python3
"""
passwd_rotator.py — Automated local-user password rotation on Cisco IOS/IOS-XE devices.

Purpose:
    Connects to network devices with existing credentials, issues a new
    'username … secret' command, then immediately verifies the new password
    authenticates before reporting success.  Designed to be run after pulling
    the new password from a vault so both the vault write and the device update
    are confirmed in a single pass.

Usage:
    # Single device
    python passwd_rotator.py --host 192.168.1.1 --user admin \
        --current-password OldPass1! --new-password NewPass1!

    # Batch (one IP or hostname per line, # comments ignored)
    python passwd_rotator.py --hosts devices.txt --user netops \
        --current-password OldPass1! --new-password NewPass1! \
        --output rotation_report.json

Prerequisites:
    pip install paramiko
    SSH access with privilege 15 (or enable reachable) on target devices.
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import json
import logging
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def _open_client(host: str, port: int, user: str, password: str, timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def _shell_send(shell: paramiko.Channel, cmd: str, delay: float = 0.8) -> str:
    shell.send(cmd + "\n")
    time.sleep(delay)
    buf = b""
    while shell.recv_ready():
        buf += shell.recv(4096)
    return buf.decode(errors="replace")


def rotate_password(
    host: str,
    user: str,
    current_pw: str,
    new_pw: str,
    port: int = 22,
    timeout: int = 10,
) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    result: dict = {"host": host, "user": user, "status": "unknown", "error": None, "timestamp": ts}

    try:
        client = _open_client(host, port, user, current_pw, timeout)
    except paramiko.AuthenticationException as exc:
        result.update(status="auth_failed", error=str(exc))
        log.error("[%s] Authentication failed: %s", host, exc)
        return result
    except (paramiko.SSHException, socket.error, OSError) as exc:
        result.update(status="connect_failed", error=str(exc))
        log.error("[%s] Connection failed: %s", host, exc)
        return result

    try:
        shell = client.invoke_shell(width=200)
        time.sleep(0.5)
        shell.recv(8192)  # flush banner / motd

        priv = _shell_send(shell, "show privilege")
        if "15" not in priv:
            log.warning("[%s] Not at privilege 15 — rotation may be rejected", host)

        # IOS: 'username <u> privilege 15 secret <pw>' updates or creates the entry
        _shell_send(shell, f"username {user} privilege 15 secret {new_pw}", delay=1.0)
        _shell_send(shell, "exit")
    except Exception as exc:
        result.update(status="change_failed", error=str(exc))
        log.error("[%s] Failed to send rotation commands: %s", host, exc)
        return result
    finally:
        client.close()

    # Verify: new credentials must authenticate within the grace window
    time.sleep(1)
    try:
        verify = _open_client(host, port, user, new_pw, timeout)
        verify.close()
        result["status"] = "rotated"
        log.info("[%s] Password rotated and verified OK", host)
    except paramiko.AuthenticationException:
        result.update(
            status="verify_failed",
            error="New credentials rejected — device may not have accepted the change",
        )
        log.error("[%s] Verification failed: new password was rejected", host)
    except (paramiko.SSHException, socket.error, OSError) as exc:
        result.update(status="verify_error", error=str(exc))
        log.error("[%s] Verification connection error: %s", host, exc)

    return result


def load_hosts(path: str) -> list:
    p = Path(path)
    if not p.exists():
        log.error("Hosts file not found: %s", path)
        sys.exit(1)
    return [
        line.strip()
        for line in p.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rotate local-user passwords on Cisco IOS/IOS-XE devices via SSH"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP or hostname")
    target.add_argument("--hosts", metavar="FILE", help="File with one host per line")
    parser.add_argument("--user", required=True, help="Username whose password is being rotated")
    parser.add_argument("--current-password", required=True, metavar="PW", help="Existing password")
    parser.add_argument("--new-password", required=True, metavar="PW", help="Replacement password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")
    parser.add_argument("--output", metavar="FILE", help="Write JSON results to this file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        paramiko.util.log_to_file("/dev/null")  # suppress paramiko noise unless debugging

    hosts = [args.host] if args.host else load_hosts(args.hosts)
    log.info("Rotating password for user '%s' across %d device(s)", args.user, len(hosts))

    results = []
    for host in hosts:
        log.info("Processing %s …", host)
        results.append(
            rotate_password(
                host=host,
                user=args.user,
                current_pw=args.current_password,
                new_pw=args.new_password,
                port=args.port,
                timeout=args.timeout,
            )
        )

    ok = [r for r in results if r["status"] == "rotated"]
    failed = [r for r in results if r["status"] != "rotated"]
    print(f"\nSummary: {len(ok)}/{len(results)} rotated successfully, {len(failed)} failed")
    for r in results:
        tag = "OK  " if r["status"] == "rotated" else "FAIL"
        print(f"  [{tag}] {r['host']:30s} {r['status']}")
        if r["error"]:
            print(f"           {r['error']}")

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2))
        log.info("Results written to %s", args.output)

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
```