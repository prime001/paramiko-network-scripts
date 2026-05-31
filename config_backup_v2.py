```python
"""
running_startup_sync.py - Detect and optionally resolve running vs startup config drift.

Purpose:
    Connects to a network device via SSH and compares the running configuration
    against the startup configuration to detect unsaved changes. Optionally saves
    the running config to startup (write memory) when drift is found.

Usage:
    python running_startup_sync.py -H 192.168.1.1 -u admin -p secret
    python running_startup_sync.py -H 192.168.1.1 -u admin -p secret --save
    python running_startup_sync.py -H 192.168.1.1 -u admin -k ~/.ssh/id_rsa --save

Prerequisites:
    pip install paramiko
"""

import argparse
import difflib
import logging
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _recv_until_prompt(channel, timeout=15, chunk_size=4096):
    """Read channel output until prompt character or timeout."""
    output = ""
    channel.settimeout(timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(chunk_size).decode("utf-8", errors="replace")
            output += chunk
            stripped = output.rstrip()
            if stripped.endswith("#") or stripped.endswith(">"):
                break
        else:
            time.sleep(0.1)
    return output


def _run_command(channel, command, timeout=30):
    """Send command and return output (strips echoed command and prompt)."""
    channel.send(command + "\n")
    raw = _recv_until_prompt(channel, timeout=timeout)
    lines = raw.splitlines()
    body = lines[1:-1] if len(lines) > 2 else lines
    return "\n".join(body)


def connect(host, port, username, password, key_filename, timeout):
    """Return an authenticated paramiko SSHClient."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_filename:
        connect_kwargs["key_filename"] = key_filename
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def check_sync(host, port, username, password, key_filename, timeout, save_on_drift):
    """
    Connect to device, compare running vs startup config.

    Returns True if configs are in sync (or drift was saved), False on unresolved drift.
    """
    client = None
    try:
        logger.info("Connecting to %s:%d", host, port)
        client = connect(host, port, username, password, key_filename, timeout)

        channel = client.invoke_shell()
        _recv_until_prompt(channel, timeout=10)

        _run_command(channel, "terminal length 0", timeout=10)

        logger.info("Fetching running-config")
        running = _run_command(channel, "show running-config", timeout=60)

        logger.info("Fetching startup-config")
        startup = _run_command(channel, "show startup-config", timeout=60)

        diff = list(
            difflib.unified_diff(
                startup.splitlines(),
                running.splitlines(),
                fromfile="startup-config",
                tofile="running-config",
                lineterm="",
            )
        )

        if not diff:
            logger.info("SYNC OK: running-config matches startup-config on %s", host)
            return True

        logger.warning("DRIFT DETECTED on %s — %d diff lines", host, len(diff))
        for line in diff[:40]:
            print(line)
        if len(diff) > 40:
            print(f"... and {len(diff) - 40} more lines")

        if save_on_drift:
            logger.info("Saving running-config to startup-config on %s", host)
            save_output = _run_command(channel, "write memory", timeout=30)
            logger.info("Save result: %s", save_output.strip())
            return True

        return False

    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        return False
    except paramiko.SSHException as exc:
        logger.error("SSH error on %s: %s", host, exc)
        return False
    except OSError as exc:
        logger.error("Connection error on %s: %s", host, exc)
        return False
    finally:
        if client:
            client.close()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Detect running vs startup config drift on a network device."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-P", "--port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default="", help="SSH password")
    parser.add_argument("-k", "--key-file", dest="key_file", help="Path to SSH private key")
    parser.add_argument(
        "-t", "--timeout", type=int, default=30, help="Connection timeout in seconds"
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Write memory on device if drift is detected",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if not args.password and not args.key_file:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    synced = check_sync(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        key_filename=args.key_file,
        timeout=args.timeout,
        save_on_drift=args.save,
    )
    sys.exit(0 if synced else 1)
```