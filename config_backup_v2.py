config_backup_rotate.py — Rolling config backup with retention management.

Purpose:
    SSH to one or more network devices, capture the running configuration,
    and persist it locally with a timestamped filename.  Old backups beyond
    a configurable retention count are pruned automatically.  An MD5
    checksum is written alongside each backup so integrity can be verified
    later.  Multiple devices are processed in parallel via a thread pool.

Usage:
    # Single device
    python config_backup_rotate.py -H 192.168.1.1 -u admin -p secret

    # Inventory file (one host per line or JSON list)
    python config_backup_rotate.py --inventory hosts.json -u admin -p secret

    # Keep only last 5 backups per device; save to custom directory
    python config_backup_rotate.py -H 192.168.1.1 -u admin -p secret \
        --keep 5 --output-dir /net/backups

    # Verify last backup matches live device (no new file written)
    python config_backup_rotate.py -H 192.168.1.1 -u admin -p secret --verify

Prerequisites:
    pip install paramiko
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import paramiko

LOG = logging.getLogger(__name__)


def _ssh_connect(
    host: str, username: str, password: str, port: int, timeout: int
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _fetch_config(client: paramiko.SSHClient) -> str:
    _, stdout, stderr = client.exec_command("show running-config", timeout=30)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        LOG.debug("stderr from device: %s", err)
    return output


def _stable_hash(config: str) -> str:
    """MD5 of config with timestamp comment lines stripped for stable comparison."""
    lines = [
        line for line in config.splitlines()
        if not re.match(r"^\s*!.*\d{2}:\d{2}:\d{2}", line)
    ]
    return hashlib.md5("\n".join(lines).encode("utf-8")).hexdigest()


def _latest_backup(device_dir: Path) -> Path | None:
    backups = sorted(device_dir.glob("*.cfg"))
    return backups[-1] if backups else None


def _prune_old_backups(device_dir: Path, keep: int) -> None:
    backups = sorted(device_dir.glob("*.cfg"))
    for old in backups[:-keep]:
        old.unlink()
        sidecar = old.with_suffix(".md5")
        if sidecar.exists():
            sidecar.unlink()
        LOG.debug("Pruned %s", old.name)


def backup_device(
    host: str,
    username: str,
    password: str,
    port: int,
    timeout: int,
    output_dir: Path,
    keep: int,
    verify_only: bool,
) -> dict:
    result = {"host": host, "status": "error", "file": None, "changed": None, "error": None}
    device_dir = output_dir / re.sub(r"[^\w.-]", "_", host)

    try:
        client = _ssh_connect(host, username, password, port, timeout)
    except Exception as exc:
        result["error"] = f"Connection failed: {exc}"
        LOG.error("[%s] %s", host, result["error"])
        return result

    try:
        config = _fetch_config(client)
    except Exception as exc:
        result["error"] = f"Command failed: {exc}"
        LOG.error("[%s] %s", host, result["error"])
        return result
    finally:
        client.close()

    if not config.strip():
        result["error"] = "Empty config received"
        LOG.warning("[%s] %s", host, result["error"])
        return result

    live_hash = _stable_hash(config)

    if verify_only:
        last = _latest_backup(device_dir)
        if last is None:
            result["error"] = "No previous backup to verify against"
            return result
        sidecar = last.with_suffix(".md5")
        if not sidecar.exists():
            result["error"] = "Missing .md5 sidecar for last backup"
            return result
        stored_hash = sidecar.read_text().split()[0]
        match = live_hash == stored_hash
        result.update({"status": "ok", "changed": not match, "file": str(last)})
        level = logging.WARNING if not match else logging.INFO
        LOG.log(level, "[%s] Verify: %s (stored=%s live=%s)",
                host, "CHANGED" if not match else "UNCHANGED", stored_hash[:8], live_hash[:8])
        return result

    device_dir.mkdir(parents=True, exist_ok=True)

    last = _latest_backup(device_dir)
    if last:
        sidecar = last.with_suffix(".md5")
        if sidecar.exists():
            stored_hash = sidecar.read_text().split()[0]
            if stored_hash == live_hash:
                result.update({"status": "ok", "changed": False, "file": str(last)})
                LOG.info("[%s] Unchanged — skipping write (md5=%s)", host, live_hash[:8])
                return result

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = device_dir / f"{timestamp}.cfg"
    backup_file.write_text(config, encoding="utf-8")
    backup_file.with_suffix(".md5").write_text(f"{live_hash}  {backup_file.name}\n")

    _prune_old_backups(device_dir, keep)

    result.update({"status": "ok", "changed": True, "file": str(backup_file)})
    LOG.info("[%s] Saved %s (md5=%s)", host, backup_file.name, live_hash[:8])
    return result


def load_inventory(path: str) -> list[str]:
    with open(path) as fh:
        if path.endswith(".json"):
            data = json.load(fh)
            return [str(h) for h in (data if isinstance(data, list) else [data])]
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rolling config backup with retention and integrity verification"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-H", "--host", help="Device hostname or IP")
    target.add_argument("--inventory", help="Inventory file (.json or plain text, one host per line)")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=15, help="SSH connect timeout (default: 15s)")
    parser.add_argument("--keep", type=int, default=10, help="Backups retained per device (default: 10)")
    parser.add_argument("--output-dir", default="backups", help="Root backup directory (default: ./backups)")
    parser.add_argument("--workers", type=int, default=5, help="Parallel threads (default: 5)")
    parser.add_argument("--verify", action="store_true", help="Compare live config to last backup; no file written")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )
    paramiko.util.log_to_file(os.devnull)

    hosts = [args.host] if args.host else load_inventory(args.inventory)
    output_dir = Path(args.output_dir)
    mode = "Verifying" if args.verify else "Backing up"
    LOG.info("%s %d device(s) → %s", mode, len(hosts), output_dir)

    results = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(hosts))) as pool:
        futures = {
            pool.submit(
                backup_device,
                h, args.username, args.password,
                args.port, args.timeout, output_dir, args.keep, args.verify,
            ): h
            for h in hosts
        }
        for future in as_completed(futures):
            results.append(future.result())

    ok = [r for r in results if r["status"] == "ok"]
    failed = [r for r in results if r["status"] != "ok"]
    changed = [r for r in ok if r.get("changed")]

    print(f"\n{'Verify' if args.verify else 'Backup'} complete: "
          f"{len(ok)} ok, {len(failed)} failed"
          + (f", {len(changed)} changed" if not args.verify else ""))
    for r in failed:
        print(f"  FAIL  {r['host']}: {r['error']}")
    if args.verify:
        for r in ok:
            state = "CHANGED" if r["changed"] else "ok"
            print(f"  {state:<8}{r['host']}")

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()