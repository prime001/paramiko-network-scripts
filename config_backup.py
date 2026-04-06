```python
"""
config_backup.py - Network Device Configuration Backup Tool

Purpose:
    Connect to network devices via SSH and retrieve their running/startup
    configurations, saving them locally with timestamps for version tracking.

Usage:
    Single device:
        python config_backup.py --host 192.168.1.1 --username admin --password secret

    From inventory file:
        python config_backup.py --inventory hosts.txt --username admin --key-file ~/.ssh/id_rsa

    With custom output directory:
        python config_backup.py --host 10.0.0.1 -u admin -p secret --output-dir /backups

Prerequisites:
    - Python 3.8+
    - paramiko: pip install paramiko
    - SSH access to target devices
    - Credentials with privilege level to run 'show running-config' (or equivalent)

Inventory file format (one host per line, optionally with port):
    192.168.1.1
    10.0.0.1:2222
    router.example.com
"""

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

BACKUP_COMMANDS = {
    "ios": "show running-config",
    "eos": "show running-config",
    "nxos": "show running-config",
    "junos": "show configuration",
    "generic": "show running-config",
}


def connect(host: str, port: int, username: str, password: str = None,
            key_file: str = None, timeout: int = 30) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if key_file:
        connect_kwargs["key_filename"] = os.path.expanduser(key_file)
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError(f"[{host}] Must provide either --password or --key-file")

    client.connect(**connect_kwargs)
    return client


def fetch_config(client: paramiko.SSHClient, host: str,
                 os_type: str = "generic") -> str:
    command = BACKUP_COMMANDS.get(os_type, BACKUP_COMMANDS["generic"])
    log.debug("[%s] Running: %s", host, command)
    stdin, stdout, stderr = client.exec_command(command, timeout=60)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace").strip()
    if error:
        log.warning("[%s] stderr: %s", host, error)
    if not output.strip():
        raise RuntimeError(f"[{host}] Empty response from '{command}'")
    return output


def save_backup(host: str, config: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = host.replace(":", "_")
    filename = output_dir / f"{safe_host}_{timestamp}.cfg"
    filename.write_text(config, encoding="utf-8")
    return filename


def backup_device(host: str, port: int, username: str, password: str,
                  key_file: str, os_type: str, output_dir: Path,
                  timeout: int) -> bool:
    log.info("[%s] Connecting on port %d", host, port)
    client = None
    try:
        client = connect(host, port, username, password, key_file, timeout)
        config = fetch_config(client, host, os_type)
        saved_path = save_backup(host, config, output_dir)
        log.info("[%s] Backup saved: %s (%d bytes)", host, saved_path,
                 saved_path.stat().st_size)
        return True
    except paramiko.AuthenticationException:
        log.error("[%s] Authentication failed", host)
    except paramiko.NoValidConnectionsError as exc:
        log.error("[%s] Connection refused: %s", host, exc)
    except (paramiko.SSHException, OSError) as exc:
        log.error("[%s] SSH error: %s", host, exc)
    except RuntimeError as exc:
        log.error("%s", exc)
    finally:
        if client:
            client.close()
    return False


def load_inventory(path: str) -> list[tuple[str, int]]:
    hosts = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                host, port_str = line.rsplit(":", 1)
                hosts.append((host, int(port_str)))
            else:
                hosts.append((line, 22))
    return hosts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Backup running configurations from network devices via SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", metavar="HOST",
                        help="Single device hostname or IP")
    target.add_argument("--inventory", metavar="FILE",
                        help="File with one host[:port] per line")

    parser.add_argument("-u", "--username", required=True,
                        help="SSH username")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("-p", "--password", help="SSH password")
    auth.add_argument("--key-file", metavar="PATH",
                      help="Path to SSH private key (default: no key auth)")

    parser.add_argument("--port", type=int, default=22,
                        help="SSH port for --host mode (default: 22)")
    parser.add_argument("--os-type",
                        choices=list(BACKUP_COMMANDS.keys()),
                        default="generic",
                        help="Device OS type to select backup command "
                             "(default: generic)")
    parser.add_argument("--output-dir", default="backups", metavar="DIR",
                        help="Directory to store backup files (default: backups)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="SSH connection timeout in seconds (default: 30)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    output_dir = Path(args.output_dir)

    if args.host:
        targets = [(args.host, args.port)]
    else:
        try:
            targets = load_inventory(args.inventory)
        except (OSError, ValueError) as e:
            log.error("Failed to load inventory: %s", e)
            sys.exit(1)

    if not targets:
        log.error("No hosts to process")
        sys.exit(1)

    log.info("Starting backup for %d device(s)", len(targets))
    results = {"ok": 0, "fail": 0}

    for host, port in targets:
        success = backup_device(
            host=host,
            port=port,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            os_type=args.os_type,
            output_dir=output_dir,
            timeout=args.timeout,
        )
        if success:
            results["ok"] += 1
        else:
            results["fail"] += 1

    log.info("Done. Success: %d  Failed: %d", results["ok"], results["fail"])
    if results["fail"] > 0:
        sys.exit(1)
```