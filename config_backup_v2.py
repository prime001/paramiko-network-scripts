```python
"""
config_archive.py - Versioned Configuration Archiver for Network Devices

Purpose:
    Pulls running configurations from network devices via SSH and archives them
    in a local Git repository, providing automatic version history, change
    detection, and retention management. Unlike a simple backup, this script
    tracks changes over time and only commits when the config has actually changed.

Usage:
    python config_archive.py -d 192.168.1.1 -u admin -p secret --archive-dir ./archives
    python config_archive.py -d 10.0.0.1 -u netops --key ~/.ssh/id_rsa --tag prod-core
    python config_archive.py --device-file hosts.txt -u admin -p secret --retain 30

Prerequisites:
    pip install paramiko gitpython
    Git must be installed and available in PATH.
    SSH access to target device(s) with sufficient privilege to run 'show running-config'.
"""

import argparse
import logging
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

import paramiko

try:
    import git
except ImportError:
    git = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def fetch_running_config(host, username, password=None, key_path=None, port=22, timeout=30):
    """Connect via SSH and retrieve the running configuration."""
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
    if key_path:
        connect_kwargs["key_filename"] = key_path
        connect_kwargs["look_for_keys"] = True
    else:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
        log.info("Connected to %s", host)
    except paramiko.AuthenticationException:
        raise RuntimeError(f"Authentication failed for {host}")
    except paramiko.NoValidConnectionsError as exc:
        raise RuntimeError(f"Unable to connect to {host}:{port} — {exc}")

    try:
        stdin, stdout, stderr = client.exec_command(
            "show running-config", timeout=timeout
        )
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.warning("stderr from %s: %s", host, err)
        if not output.strip():
            raise RuntimeError(f"Empty response from {host}; check command and privileges")
        return output
    finally:
        client.close()


def sanitize_hostname(host):
    """Return a filesystem-safe name derived from a hostname or IP."""
    return re.sub(r"[^\w\-.]", "_", host)


def ensure_git_repo(path):
    """Initialize a git repo at path if one does not already exist."""
    if git is None:
        log.warning("gitpython not installed; skipping version control")
        return None
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if (path / ".git").exists():
        repo = git.Repo(path)
    else:
        repo = git.Repo.init(path)
        log.info("Initialized git repository at %s", path)
    return repo


def archive_config(archive_dir, host, tag, config_text, repo):
    """Write config to disk and commit if contents changed."""
    label = tag if tag else sanitize_hostname(host)
    device_dir = Path(archive_dir) / label
    device_dir.mkdir(parents=True, exist_ok=True)

    config_file = device_dir / "running-config.txt"
    previous = config_file.read_text() if config_file.exists() else None

    if previous == config_text:
        log.info("[%s] No change detected; skipping archive", label)
        return False

    config_file.write_text(config_text)
    log.info("[%s] Config written to %s", label, config_file)

    if repo is not None:
        try:
            repo.index.add([str(config_file.relative_to(archive_dir))])
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            commit_msg = f"[{label}] config snapshot {timestamp}"
            repo.index.commit(commit_msg)
            log.info("[%s] Committed: %s", label, commit_msg)
        except Exception as exc:
            log.warning("[%s] Git commit failed: %s", label, exc)

    return True


def prune_old_commits(repo, retain_days):
    """Log a warning; branch-based pruning requires more complex history rewriting."""
    if repo is None or retain_days <= 0:
        return
    cutoff = datetime.utcnow() - timedelta(days=retain_days)
    old = [
        c for c in repo.iter_commits()
        if datetime.utcfromtimestamp(c.committed_date) < cutoff
    ]
    if old:
        log.info("Repository has %d commit(s) older than %d days (retention policy: manual prune with 'git rebase')", len(old), retain_days)


def load_device_file(path):
    """Read one host per line from a file, ignoring blank lines and comments."""
    hosts = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def parse_args():
    parser = argparse.ArgumentParser(
        description="Archive network device running configs with Git version history."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-d", "--device", help="Single device hostname or IP")
    source.add_argument("--device-file", metavar="FILE", help="File with one host per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--key", metavar="PATH", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    parser.add_argument("--archive-dir", default="./config-archive", help="Root archive directory")
    parser.add_argument("--tag", default=None, help="Label to use instead of hostname (single device only)")
    parser.add_argument("--retain", type=int, default=0, metavar="DAYS",
                        help="Warn about commits older than N days (0 = disabled)")
    parser.add_argument("--no-git", action="store_true", help="Disable Git version control")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}: ")

    hosts = [args.device] if args.device else load_device_file(args.device_file)
    if not hosts:
        log.error("No hosts to process")
        sys.exit(1)

    repo = None if args.no_git else ensure_git_repo(args.archive_dir)

    results = {"changed": 0, "unchanged": 0, "failed": 0}

    for host in hosts:
        try:
            config = fetch_running_config(
                host=host,
                username=args.username,
                password=args.password,
                key_path=args.key,
                port=args.port,
                timeout=args.timeout,
            )
            changed = archive_config(
                archive_dir=args.archive_dir,
                host=host,
                tag=args.tag if args.device else None,
                config_text=config,
                repo=repo,
            )
            results["changed" if changed else "unchanged"] += 1
        except Exception as exc:
            log.error("[%s] Failed: %s", host, exc)
            results["failed"] += 1

    if args.retain and repo:
        prune_old_commits(repo, args.retain)

    log.info(
        "Done — changed: %d, unchanged: %d, failed: %d",
        results["changed"], results["unchanged"], results["failed"],
    )
    sys.exit(1 if results["failed"] else 0)
```