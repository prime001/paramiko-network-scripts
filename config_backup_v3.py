Here's the complete script — write it to `running_startup_drift.py` in your repo:

```python
"""
running_startup_drift.py — Detect unsaved configuration changes on network devices.

Compares the running-config against the startup-config and reports any drift
(changes that would be lost if the device rebooted). Optionally writes memory
to persist the running config.

Usage:
    python running_startup_drift.py -H 192.168.1.1 -u admin -p secret
    python running_startup_drift.py -H 192.168.1.1 -u admin -p secret --save
    python running_startup_drift.py --inventory hosts.txt -u admin -p secret

Prerequisites:
    pip install paramiko
    Device must support 'show running-config' and 'show startup-config' (Cisco IOS/IOS-XE).
"""

import argparse
import difflib
import logging
import sys
import time

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

RECV_TIMEOUT = 30
RECV_BUFFER = 65535
COMMAND_DELAY = 1.5


def ssh_connect(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(shell: paramiko.Channel, command: str, delay: float = COMMAND_DELAY) -> str:
    shell.send(command + "\n")
    time.sleep(delay)
    output = []
    deadline = time.time() + RECV_TIMEOUT
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(RECV_BUFFER).decode("utf-8", errors="replace")
            output.append(chunk)
            if chunk.rstrip().endswith("#") or chunk.rstrip().endswith(">"):
                break
        else:
            time.sleep(0.2)
    return "".join(output)


def strip_config_header(config: str) -> list[str]:
    lines = []
    for line in config.splitlines():
        stripped = line.rstrip()
        if any(stripped.startswith(skip) for skip in (
            "Building configuration",
            "Current configuration",
            "Last configuration change",
            "NVRAM config",
            "version ",
        )):
            continue
        if stripped.startswith("!") and not stripped.strip("!"):
            continue
        lines.append(stripped)
    return lines


def check_drift(host: str, username: str, password: str, port: int, save: bool) -> bool:
    """Return True if drift was found, False if configs match."""
    logger.info("[%s] Connecting ...", host)
    try:
        client = ssh_connect(host, username, password, port)
    except Exception as exc:
        logger.error("[%s] Connection failed: %s", host, exc)
        return False

    try:
        shell = client.invoke_shell(width=250, height=5000)
        time.sleep(1)
        shell.recv(RECV_BUFFER)

        run_command(shell, "terminal length 0", delay=0.5)

        logger.info("[%s] Fetching running-config ...", host)
        running_raw = run_command(shell, "show running-config", delay=COMMAND_DELAY)

        logger.info("[%s] Fetching startup-config ...", host)
        startup_raw = run_command(shell, "show startup-config", delay=COMMAND_DELAY)

    except Exception as exc:
        logger.error("[%s] Command error: %s", host, exc)
        client.close()
        return False

    running_lines = strip_config_header(running_raw)
    startup_lines = strip_config_header(startup_raw)

    diff = list(difflib.unified_diff(
        startup_lines,
        running_lines,
        fromfile=f"{host}:startup-config",
        tofile=f"{host}:running-config",
        lineterm="",
    ))

    if not diff:
        logger.info("[%s] No drift — running and startup configs match.", host)
        client.close()
        return False

    print(f"\n{'='*60}")
    print(f"DRIFT DETECTED on {host}")
    print(f"{'='*60}")
    changed = [l for l in diff if l.startswith(("+", "-")) and not l.startswith(("---", "+++"))]
    print(f"{len(changed)} line(s) differ:\n")
    for line in diff:
        print(line)

    if save:
        logger.info("[%s] Saving running-config to startup-config (write memory) ...", host)
        try:
            result = run_command(shell, "write memory", delay=3.0)
            if "OK" in result or "Building configuration" in result:
                logger.info("[%s] Save succeeded.", host)
            else:
                logger.warning("[%s] Save result unclear — check device: %s", host, result.strip())
        except Exception as exc:
            logger.error("[%s] Save failed: %s", host, exc)

    client.close()
    return True


def parse_inventory(path: str) -> list[str]:
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except OSError as exc:
        logger.error("Cannot read inventory file: %s", exc)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect unsaved config drift (running vs startup) on Cisco devices."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--host", help="Single device IP or hostname")
    group.add_argument("--inventory", metavar="FILE", help="File with one host per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--save",
        action="store_true",
        help="Write memory on devices that have drift",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    hosts = [args.host] if args.host else parse_inventory(args.inventory)

    drifted = []
    for host in hosts:
        had_drift = check_drift(host, args.username, args.password, args.port, args.save)
        if had_drift:
            drifted.append(host)

    print(f"\nSummary: {len(drifted)}/{len(hosts)} device(s) have unsaved changes.")
    if drifted:
        print("Drifted:", ", ".join(drifted))
        sys.exit(1)


if __name__ == "__main__":
    main()
```

**What this does and why it's distinct from existing scripts:**

- `config_backup*` — saves configs to files on disk
- `config_diff*` — diffs configs across devices or backup files
- **This script** — fetches both `running-config` and `startup-config` from the same device in one session and diffs them to surface unsaved changes that would be lost on reboot

**Key design decisions:**
- `strip_config_header()` removes timestamps and version lines that always differ and would produce false positives
- `--save` flag optionally runs `write memory` only on devices that actually have drift, making it safe for pre-maintenance-window automation
- Exit code 1 when any device has drift, so it integrates cleanly into CI/monitoring pipelines
- Inventory file support with `#` comments for fleet-wide checks