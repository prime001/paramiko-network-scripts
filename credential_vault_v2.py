credential_rotation.py — Automated SSH credential rotation for network devices.

Purpose:
    Connect to one or more network devices via SSH and rotate (change) a user
    account password, then immediately verify the new credentials before
    considering the rotation successful.  Supports Cisco IOS/IOS-XE
    (username secret syntax + write memory) and a generic fallback for
    Linux/Unix hosts (passwd flow).

Usage:
    # Single host — passwords prompted interactively
    python credential_rotation.py --host 192.168.1.1 --username netops

    # Single host — passwords supplied on CLI (CI/CD use)
    python credential_rotation.py --host 192.168.1.1 --username netops \
        --current-password OldP@ss1 --new-password NewP@ss2

    # Multiple hosts from a file (one IP/hostname per line, # = comment)
    python credential_rotation.py --hosts-file devices.txt \
        --username netops --platform ios

Prerequisites:
    pip install paramiko
"""

import argparse
import getpass
import logging
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def _shell_send(shell, command: str, delay: float = 1.0, buf: int = 65535) -> str:
    shell.send(command + "\n")
    time.sleep(delay)
    chunks = []
    while shell.recv_ready():
        chunks.append(shell.recv(buf).decode("utf-8", errors="replace"))
    return "".join(chunks)


def _rotate_ios(shell, username: str, new_password: str) -> bool:
    out = _shell_send(shell, f"username {username} secret {new_password}", delay=1.5)
    if "Invalid" in out or "Error" in out:
        log.error("IOS rejected the password change command: %s", out.strip())
        return False
    _shell_send(shell, "write memory", delay=2.0)
    log.debug("IOS write memory issued")
    return True


def _rotate_generic(shell, new_password: str) -> bool:
    """passwd-style rotation for Linux/Unix SSH targets."""
    _shell_send(shell, "passwd", delay=1.0)
    out1 = _shell_send(shell, new_password, delay=1.0)
    out2 = _shell_send(shell, new_password, delay=1.0)
    combined = (out1 + out2).lower()
    return "successfully" in combined or "updated" in combined or "changed" in combined


def _verify_login(host: str, port: int, username: str, password: str) -> bool:
    """Open a fresh SSH connection to confirm the new password works."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as exc:
        log.warning("[%s] Verification connect error: %s", host, exc)
        return False
    finally:
        client.close()


def rotate_device(
    host: str,
    port: int,
    username: str,
    current_password: str,
    new_password: str,
    platform: str,
) -> bool:
    """Rotate credentials on a single device; return True on verified success."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        log.info("[%s] Connecting on port %d …", host, port)
        client.connect(
            host,
            port=port,
            username=username,
            password=current_password,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(1.2)
        shell.recv(65535)  # drain banner / MOTD

        if platform == "ios":
            _shell_send(shell, "terminal length 0", delay=0.5)
            ok = _rotate_ios(shell, username, new_password)
        else:
            ok = _rotate_generic(shell, new_password)

        shell.close()

        if not ok:
            log.error("[%s] Rotation command reported failure", host)
            return False

    except paramiko.AuthenticationException:
        log.error("[%s] Authentication failed with current credentials", host)
        return False
    except paramiko.SSHException as exc:
        log.error("[%s] SSH error: %s", host, exc)
        return False
    except OSError as exc:
        log.error("[%s] Network error: %s", host, exc)
        return False
    finally:
        client.close()

    log.info("[%s] Verifying new credentials …", host)
    if _verify_login(host, port, username, new_password):
        log.info("[%s] Rotation SUCCEEDED — new credentials verified", host)
        return True

    log.error(
        "[%s] Verification FAILED — new credentials do not work; manual intervention required",
        host,
    )
    return False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Rotate SSH credentials on network devices and verify success.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP or hostname")
    target.add_argument(
        "--hosts-file",
        metavar="FILE",
        help="Text file listing one host per line (# lines ignored)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--username", required=True, help="Account whose password is rotated")
    p.add_argument(
        "--current-password",
        help="Current password (interactive prompt if omitted)",
    )
    p.add_argument(
        "--new-password",
        help="Replacement password (interactive prompt if omitted)",
    )
    p.add_argument(
        "--platform",
        choices=["ios", "generic"],
        default="ios",
        help="ios = Cisco IOS/IOS-XE (username secret); generic = Linux passwd flow",
    )
    p.add_argument("--debug", action="store_true", help="Enable DEBUG logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    current_pw = args.current_password or getpass.getpass("Current password: ")
    new_pw = args.new_password or getpass.getpass("New password: ")

    if args.host:
        hosts = [args.host.strip()]
    else:
        try:
            with open(args.hosts_file) as fh:
                hosts = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except OSError as exc:
            log.error("Cannot read hosts file: %s", exc)
            sys.exit(1)

    if not hosts:
        log.error("No hosts to process")
        sys.exit(1)

    succeeded, failed = [], []
    for host in hosts:
        ok = rotate_device(
            host=host,
            port=args.port,
            username=args.username,
            current_password=current_pw,
            new_password=new_pw,
            platform=args.platform,
        )
        (succeeded if ok else failed).append(host)

    print(f"\nRotation complete — {len(succeeded)} succeeded, {len(failed)} failed")
    if failed:
        print("Failed hosts:", ", ".join(failed))
        sys.exit(1)