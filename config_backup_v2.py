The user's instruction says "Output ONLY the script content" — here it is:

#!/usr/bin/env python3
"""
git_config_vault.py - Network device configuration backup with Git versioning.

Connects to a network device via SSH, retrieves the running configuration,
and commits it to a local Git repository. Each backup creates a timestamped
commit, providing a full audit trail and enabling diff/rollback via standard
Git tooling — no external tooling required beyond git itself.

Usage:
    python git_config_vault.py --host 192.168.1.1 --username admin \
        --repo /var/backups/network-configs [--port 22] [--key-file ~/.ssh/id_rsa]

    # View history for a device:
    git -C /var/backups/network-configs log --oneline -- 192.168.1.1.cfg

Prerequisites:
    - Python 3.10+
    - paramiko: pip install paramiko
    - git installed and available in PATH
    - SSH access to the target device
    - Write permission on the repo directory (created automatically if absent)
"""

import argparse
import getpass
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def get_running_config(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    key_file: str | None = None,
    timeout: int = 30,
) -> str:
    """SSH to device, run 'show running-config', return output."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        connect_kwargs["key_filename"] = key_file
        connect_kwargs["look_for_keys"] = True
    elif password:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
        log.info("Connected to %s:%d as %s", host, port, username)

        _, stdout, stderr = client.exec_command("show running-config", timeout=60)
        config = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()

        if err:
            log.warning("Device stderr: %s", err)
        if not config.strip():
            raise RuntimeError(
                "Empty response — verify 'show running-config' is supported on this device"
            )
        log.debug("Retrieved %d bytes from %s", len(config), host)
        return config
    finally:
        client.close()


def ensure_git_repo(repo_path: Path) -> None:
    """Initialize a Git repo with a bot identity if it doesn't already exist."""
    if (repo_path / ".git").exists():
        return

    log.info("Initializing new Git repo at %s", repo_path)
    repo_path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(repo_path)], check=True, capture_output=True)
    for key, val in [("user.email", "netauto@localhost"), ("user.name", "NetAutoCommitter")]:
        subprocess.run(
            ["git", "-C", str(repo_path), "config", key, val],
            check=True,
            capture_output=True,
        )


def commit_config(repo_path: Path, host: str, config: str) -> str | None:
    """
    Write <host>.cfg and commit it. Returns the short SHA on a new commit,
    or None when the config is identical to the last backup (no commit made).
    """
    config_file = repo_path / f"{host}.cfg"
    config_file.write_text(config, encoding="utf-8")

    status = subprocess.run(
        ["git", "-C", str(repo_path), "status", "--porcelain", config_file.name],
        check=True,
        capture_output=True,
        text=True,
    )
    if not status.stdout.strip():
        log.info("No change in config for %s — skipping commit", host)
        return None

    subprocess.run(
        ["git", "-C", str(repo_path), "add", config_file.name],
        check=True,
        capture_output=True,
    )
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit_msg = f"backup({host}): running-config @ {ts}"
    subprocess.run(
        ["git", "-C", str(repo_path), "commit", "-m", commit_msg],
        check=True,
        capture_output=True,
    )

    sha = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--short", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    log.info("Committed %s → %s", host, sha)
    return sha


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Back up a network device's running-config to a Git repository.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--username", required=True, help="SSH login username")
    p.add_argument("--password", help="SSH password (prompted if omitted and --key-file absent)")
    p.add_argument("--key-file", help="Path to SSH private key")
    p.add_argument(
        "--repo",
        default="./config-backups",
        help="Local directory to use as the Git config store",
    )
    p.add_argument("--timeout", type=int, default=30, help="SSH connection timeout in seconds")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable debug-level output")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    password = args.password
    if not args.key_file and not password:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    repo_path = Path(args.repo).expanduser().resolve()

    try:
        ensure_git_repo(repo_path)
        config = get_running_config(
            host=args.host,
            port=args.port,
            username=args.username,
            password=password,
            key_file=args.key_file,
            timeout=args.timeout,
        )
        sha = commit_config(repo_path, args.host, config)
        if sha:
            print(f"Backup committed: {sha}")
            print(f"View history: git -C {repo_path} log --oneline -- {args.host}.cfg")
        else:
            print("No changes since last backup.")
        sys.exit(0)

    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("SSH/network error: %s", exc)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        log.error("Git command failed: %s", stderr.strip() or exc)
        sys.exit(1)
    except RuntimeError as exc:
        log.error("%s", exc)
        sys.exit(1)