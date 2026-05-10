SSH Key Lifecycle Manager for Network Devices

Manages SSH public key authentication on network devices: deploy keys for
password-less access, verify key-based login works, audit installed keys,
and remove stale keys. Useful for transitioning device fleets from password
auth to key-based auth, auditing key hygiene, or rotating compromised keys.

Usage:
    # Deploy your public key using password auth
    python credential_vault_v3.py --host 192.168.1.1 --username admin \
        --password secret --action deploy --pubkey ~/.ssh/id_rsa.pub

    # Verify key-based login succeeds after deployment
    python credential_vault_v3.py --host 192.168.1.1 --username admin \
        --key ~/.ssh/id_rsa --action verify

    # Audit which keys are installed (accepts password or key auth)
    python credential_vault_v3.py --host 192.168.1.1 --username admin \
        --password secret --action audit

    # Remove a specific key by its public key file
    python credential_vault_v3.py --host 192.168.1.1 --username admin \
        --password secret --action remove --pubkey ~/.ssh/id_rsa_old.pub

Prerequisites:
    pip install paramiko
    Target must have sshd running and support authorized_keys (Linux-based
    network devices, Cisco NX-OS with bash shell, Arista EOS, Juniper JunOS).
    For Cisco IOS, SSH key auth requires 'ip ssh pubkey-chain' configuration.
"""

import argparse
import logging
import sys
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def _connect(host, port, username, password=None, key_path=None, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = str(key_path)
    if password:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _run(client, command, timeout=10):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    return (
        stdout.read().decode(errors="replace").strip(),
        stderr.read().decode(errors="replace").strip(),
    )


def deploy_key(host, port, username, password, pubkey_path, timeout):
    pubkey_text = Path(pubkey_path).read_text().strip()
    client = _connect(host, port, username, password=password, timeout=timeout)
    try:
        _run(client, "mkdir -p ~/.ssh && chmod 700 ~/.ssh")
        out, err = _run(
            client,
            "cat ~/.ssh/authorized_keys 2>/dev/null || true",
        )
        if pubkey_text in out:
            log.info("Key already present on %s — no change needed", host)
            return True
        sftp = client.open_sftp()
        existing = out + "\n" if out else ""
        with sftp.open(".ssh/authorized_keys", "w") as f:
            f.write(existing + pubkey_text + "\n")
        sftp.close()
        _run(client, "chmod 600 ~/.ssh/authorized_keys")
        log.info("Key deployed to %s@%s", username, host)
        return True
    except Exception as exc:
        log.error("Deploy failed on %s: %s", host, exc)
        return False
    finally:
        client.close()


def verify_key_auth(host, port, username, key_path, timeout):
    try:
        client = _connect(host, port, username, key_path=key_path, timeout=timeout)
        out, _ = _run(client, "echo KEY_AUTH_OK")
        client.close()
        if "KEY_AUTH_OK" in out:
            log.info("Key auth verified for %s@%s", username, host)
            return True
        log.warning("Unexpected response from %s during verify: %s", host, out)
        return False
    except paramiko.AuthenticationException:
        log.error("Key auth FAILED for %s@%s — key not accepted by device", username, host)
        return False
    except Exception as exc:
        log.error("Verify error on %s: %s", host, exc)
        return False


def audit_keys(host, port, username, password=None, key_path=None, timeout=15):
    client = _connect(
        host, port, username, password=password, key_path=key_path, timeout=timeout
    )
    try:
        out, _ = _run(client, "cat ~/.ssh/authorized_keys 2>/dev/null || true")
        keys = [
            line for line in out.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not keys:
            log.info("No authorized keys found for %s@%s", username, host)
            return []
        log.info("%d key(s) installed for %s@%s:", len(keys), username, host)
        for i, k in enumerate(keys, 1):
            parts = k.split()
            if len(parts) >= 2:
                summary = f"{parts[0]} ...{parts[1][-20:]} {' '.join(parts[2:])}"
            else:
                summary = k[:80]
            print(f"  [{i}] {summary.strip()}")
        return keys
    except Exception as exc:
        log.error("Audit failed on %s: %s", host, exc)
        return []
    finally:
        client.close()


def remove_key(host, port, username, password, pubkey_path, timeout):
    pubkey_text = Path(pubkey_path).read_text().strip()
    client = _connect(host, port, username, password=password, timeout=timeout)
    try:
        out, _ = _run(client, "cat ~/.ssh/authorized_keys 2>/dev/null || true")
        original = [l for l in out.splitlines() if l.strip()]
        filtered = [l for l in original if l.strip() != pubkey_text]
        if len(filtered) == len(original):
            log.warning("Key not found in authorized_keys on %s — nothing removed", host)
            return True
        sftp = client.open_sftp()
        with sftp.open(".ssh/authorized_keys", "w") as f:
            f.write("\n".join(filtered) + "\n" if filtered else "")
        sftp.close()
        log.info("Key removed from %s@%s (%d remaining)", username, host, len(filtered))
        return True
    except Exception as exc:
        log.error("Remove failed on %s: %s", host, exc)
        return False
    finally:
        client.close()


def parse_args():
    p = argparse.ArgumentParser(
        description="SSH public key lifecycle manager for network devices"
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="Password (required for deploy, audit, remove)")
    p.add_argument("--key", help="Private key path (required for verify)")
    p.add_argument("--pubkey", help="Public key file path (required for deploy, remove)")
    p.add_argument(
        "--action",
        required=True,
        choices=["deploy", "verify", "audit", "remove"],
    )
    p.add_argument("--timeout", type=int, default=15, help="SSH connect timeout (seconds)")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        paramiko.util.log_to_file("/dev/stderr")

    if args.action == "deploy":
        if not args.password or not args.pubkey:
            log.error("--password and --pubkey are required for deploy")
            sys.exit(2)
        ok = deploy_key(args.host, args.port, args.username, args.password, args.pubkey, args.timeout)

    elif args.action == "verify":
        if not args.key:
            log.error("--key (private key path) is required for verify")
            sys.exit(2)
        ok = verify_key_auth(args.host, args.port, args.username, args.key, args.timeout)

    elif args.action == "audit":
        if not args.password and not args.key:
            log.error("--password or --key is required for audit")
            sys.exit(2)
        result = audit_keys(
            args.host, args.port, args.username,
            password=args.password, key_path=args.key, timeout=args.timeout,
        )
        ok = result is not None

    elif args.action == "remove":
        if not args.password or not args.pubkey:
            log.error("--password and --pubkey are required for remove")
            sys.exit(2)
        ok = remove_key(args.host, args.port, args.username, args.password, args.pubkey, args.timeout)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()