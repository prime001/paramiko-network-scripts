```python
"""
running_vs_startup.py - Detect unsaved configuration changes on Cisco IOS devices.

Compares running-config against startup-config to identify changes that will be
lost on reboot. Useful for post-change audits and scheduled drift detection.

Usage:
    python running_vs_startup.py -d 192.168.1.1 -u admin -p secret
    python running_vs_startup.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python running_vs_startup.py -d 192.168.1.1 -u admin -p secret --save --output diff.txt

Prerequisites:
    pip install paramiko

Exit codes:
    0 - configs match (no unsaved changes)
    1 - unsaved changes detected
    2 - connection or authentication error
"""

import argparse
import difflib
import logging
import sys
import time
from pathlib import Path

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def fetch_config(channel: paramiko.Channel, command: str, timeout: int = 30) -> str:
    """Send a command and collect output until the prompt returns."""
    channel.send(command + "\n")
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if output.rstrip().endswith("#"):
                break
        else:
            time.sleep(0.1)
    return output


def strip_config_header(config: str) -> list[str]:
    """Return config lines with timestamp headers and prompts removed."""
    lines = []
    for line in config.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("!") and ("Last configuration" in stripped or "NVRAM" in stripped):
            continue
        if stripped.endswith("#") and len(stripped) < 40:
            continue
        lines.append(line.rstrip())
    return lines


def compare_configs(running: list[str], startup: list[str]) -> list[str]:
    """Return unified diff lines between startup and running config."""
    return list(
        difflib.unified_diff(
            startup,
            running,
            fromfile="startup-config",
            tofile="running-config",
            lineterm="",
        )
    )


def connect(host: str, port: int, username: str, password: str | None, key_path: str | None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 15,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        connect_kwargs["key_filename"] = key_path
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def check_unsaved_changes(
    host: str,
    port: int,
    username: str,
    password: str | None,
    key_path: str | None,
    save: bool,
    output_path: str | None,
) -> int:
    try:
        log.info("Connecting to %s:%d", host, port)
        client = connect(host, port, username, password, key_path)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        return 2
    except Exception as exc:
        log.error("Connection error: %s", exc)
        return 2

    try:
        channel = client.invoke_shell(width=250, height=1000)
        time.sleep(1)
        channel.recv(65535)

        channel.send("terminal length 0\n")
        time.sleep(0.5)
        channel.recv(65535)

        log.info("Fetching running-config")
        running_raw = fetch_config(channel, "show running-config")

        log.info("Fetching startup-config")
        startup_raw = fetch_config(channel, "show startup-config")

        running_lines = strip_config_header(running_raw)
        startup_lines = strip_config_header(startup_raw)

        diff = compare_configs(running_lines, startup_lines)

        if not diff:
            log.info("CLEAN: running-config matches startup-config on %s", host)
            client.close()
            return 0

        log.warning("DRIFT DETECTED: %d diff lines on %s", len(diff), host)
        diff_text = "\n".join(diff)
        print(diff_text)

        if output_path:
            Path(output_path).write_text(diff_text + "\n")
            log.info("Diff written to %s", output_path)

        if save:
            log.info("Saving configuration (write memory)")
            fetch_config(channel, "write memory", timeout=60)
            log.info("Configuration saved on %s", host)

        client.close()
        return 1

    except Exception as exc:
        log.error("Error during config fetch: %s", exc)
        client.close()
        return 2


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect unsaved config changes on Cisco IOS devices."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--save",
        action="store_true",
        help="Run 'write memory' if unsaved changes are found",
    )
    parser.add_argument("--output", default=None, help="Write diff output to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key:
        parser.error("Provide --password or --key for authentication")

    sys.exit(
        check_unsaved_changes(
            host=args.device,
            port=args.port,
            username=args.username,
            password=args.password,
            key_path=args.key,
            save=args.save,
            output_path=args.output,
        )
    )


if __name__ == "__main__":
    main()
```