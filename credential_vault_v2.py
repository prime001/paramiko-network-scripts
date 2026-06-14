```python
"""
ssh_key_rotator.py - SSH key rotation manager for network devices

Purpose:
    Automates RSA key pair rotation across network devices. Generates new key pairs,
    deploys public keys via password-authenticated Paramiko SSH, verifies key auth
    succeeds, and tracks rotation history with staleness auditing.

Usage:
    # Rotate keys on a single device
    python ssh_key_rotator.py rotate --host 192.168.1.1 --user admin --password secret

    # Rotate all hosts listed in a file
    python ssh_key_rotator.py rotate --host-file hosts.txt --user admin --password secret

    # Audit key age across all tracked devices
    python ssh_key_rotator.py audit --max-age 90

Prerequisites:
    pip install paramiko
    Write access to key store directory (default: ~/.ssh/net_keys/)
    Devices must support authorized_keys-based SSH key injection
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import paramiko

KEY_STORE = Path.home() / ".ssh" / "net_keys"
ROTATION_LOG = KEY_STORE / "rotation_log.json"
KEY_BITS = 2048

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


def _ensure_store():
    KEY_STORE.mkdir(parents=True, exist_ok=True)
    if not ROTATION_LOG.exists() or ROTATION_LOG.stat().st_size == 0:
        ROTATION_LOG.write_text("{}")


def _load_log():
    _ensure_store()
    return json.loads(ROTATION_LOG.read_text())


def _save_log(data):
    ROTATION_LOG.write_text(json.dumps(data, indent=2))


def generate_key_pair(host):
    key = paramiko.RSAKey.generate(KEY_BITS)
    private_path = KEY_STORE / f"{host}.pem"
    public_path = KEY_STORE / f"{host}.pub"

    key.write_private_key_file(str(private_path))
    os.chmod(private_path, 0o600)

    pub_key_str = f"ssh-rsa {key.get_base64()} net_rotation@{host}"
    public_path.write_text(pub_key_str + "\n")

    log.info("Generated %d-bit RSA key pair for %s", KEY_BITS, host)
    return str(private_path), pub_key_str


def deploy_public_key(host, port, username, password, pub_key):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, timeout=15)
        commands = [
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
            f'echo "{pub_key}" >> ~/.ssh/authorized_keys',
            "chmod 600 ~/.ssh/authorized_keys",
        ]
        for cmd in commands:
            _, stdout, stderr = client.exec_command(cmd)
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                log.error("Command failed on %s (exit %d): %s", host, exit_code,
                          stderr.read().decode().strip())
                return False
        log.info("Deployed public key to %s@%s", username, host)
        return True
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        return False
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error for %s: %s", host, exc)
        return False
    finally:
        client.close()


def verify_key_auth(host, port, username, private_key_path):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        pkey = paramiko.RSAKey.from_private_key_file(private_key_path)
        client.connect(host, port=port, username=username, pkey=pkey, timeout=10)
        client.exec_command("echo ok")
        log.info("Key auth verified for %s@%s", username, host)
        return True
    except paramiko.AuthenticationException:
        log.warning("Key auth verification FAILED for %s@%s", username, host)
        return False
    except (paramiko.SSHException, OSError) as exc:
        log.warning("Verification connect error for %s: %s", host, exc)
        return False
    finally:
        client.close()


def rotate_host(host, port, username, password):
    private_path, pub_key = generate_key_pair(host)
    if not deploy_public_key(host, port, username, password, pub_key):
        return False

    verified = verify_key_auth(host, port, username, private_path)
    data = _load_log()
    data[host] = {
        "host": host,
        "username": username,
        "private_key": private_path,
        "rotated_at": datetime.utcnow().isoformat(),
        "verified": verified,
    }
    _save_log(data)

    if verified:
        log.info("Rotation complete for %s — key auth confirmed", host)
    else:
        log.warning("Rotation complete for %s — key auth unverified (password still active)", host)
    return True


def audit_keys(max_age_days):
    data = _load_log()
    if not data:
        print("No rotation records found.")
        return

    cutoff = datetime.utcnow() - timedelta(days=max_age_days)
    rows = []
    for record in data.values():
        rotated = datetime.fromisoformat(record["rotated_at"])
        age = (datetime.utcnow() - rotated).days
        rows.append({**record, "age_days": age, "stale": rotated < cutoff})

    rows.sort(key=lambda r: r["age_days"], reverse=True)
    print(f"\n{'Host':<22} {'User':<15} {'Age':>8}  {'Verified':<9} Status")
    print("-" * 65)
    for r in rows:
        status = "STALE" if r["stale"] else "OK"
        verified = "yes" if r.get("verified") else "no"
        print(f"{r['host']:<22} {r['username']:<15} {r['age_days']:>7}d  {verified:<9} {status}")

    stale_count = sum(1 for r in rows if r["stale"])
    print(f"\nTotal: {len(rows)}  |  Stale (>{max_age_days}d): {stale_count}  |  Current: {len(rows) - stale_count}")


def main():
    parser = argparse.ArgumentParser(description="SSH key rotation manager for network devices")
    parser.add_argument("action", choices=["rotate", "audit"])
    parser.add_argument("--host", help="Target device hostname or IP")
    parser.add_argument("--host-file", help="File with one host per line")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", help="SSH username")
    parser.add_argument("--password", help="Current password for key deployment")
    parser.add_argument("--max-age", type=int, default=90,
                        help="Staleness threshold in days (audit mode, default: 90)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.action == "audit":
        audit_keys(args.max_age)
        return

    if not args.user or not args.password:
        parser.error("--user and --password are required for rotate")

    hosts = []
    if args.host:
        hosts.append(args.host)
    if args.host_file:
        try:
            hosts.extend(
                line.strip()
                for line in Path(args.host_file).read_text().splitlines()
                if line.strip() and not line.startswith("#")
            )
        except OSError as exc:
            log.error("Cannot read host file: %s", exc)
            sys.exit(1)

    if not hosts:
        parser.error("Provide --host or --host-file for rotate")

    succeeded, failed = [], []
    for host in hosts:
        log.info("--- Rotating %s ---", host)
        (succeeded if rotate_host(host, args.port, args.user, args.password) else failed).append(host)

    print(f"\nRotation summary: {len(succeeded)} succeeded, {len(failed)} failed")
    if failed:
        print("Failed:", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
```