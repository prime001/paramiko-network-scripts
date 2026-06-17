```python
"""
ssh_key_deployer.py - Deploy and audit SSH public keys on network devices.

Purpose:
    Push authorized SSH public keys to network devices, optionally rotating
    out an old key fingerprint. Also supports audit mode to report what keys
    are currently installed without making changes.

Usage:
    # Deploy a key to a single device
    python ssh_key_deployer.py -d 192.168.1.1 -u admin -p secret \
        --pubkey ~/.ssh/id_ed25519.pub

    # Audit keys on multiple devices from a file
    python ssh_key_deployer.py --hosts hosts.txt -u admin -p secret --audit

    # Rotate: add new key and remove old key by fingerprint
    python ssh_key_deployer.py -d 192.168.1.1 -u admin -p secret \
        --pubkey ~/.ssh/id_ed25519.pub --remove-fingerprint "SHA256:abc123..."

Prerequisites:
    pip install paramiko
    Target devices must permit password SSH login initially (to deploy the key).
    The deploying user must have write access to ~/.ssh/authorized_keys on target.
"""

import argparse
import hashlib
import logging
import socket
import sys
import base64
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def _ssh_client(host: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password, timeout=10)
    return client


def _run(client: paramiko.SSHClient, cmd: str) -> tuple[str, str, int]:
    _, stdout, stderr = client.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    return stdout.read().decode().strip(), stderr.read().decode().strip(), exit_code


def _pubkey_fingerprint(pubkey_line: str) -> str:
    """Return SHA256 fingerprint matching ssh-keygen -lf output."""
    parts = pubkey_line.strip().split()
    if len(parts) < 2:
        return ""
    raw = base64.b64decode(parts[1])
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode()


def audit_keys(host: str, username: str, password: str, port: int = 22) -> list[dict]:
    """Return list of dicts describing each authorized key on the device."""
    results = []
    try:
        client = _ssh_client(host, username, password, port)
        out, err, rc = _run(client, "cat ~/.ssh/authorized_keys 2>/dev/null")
        client.close()
        if rc != 0 or not out:
            log.warning("%s: no authorized_keys found or read error", host)
            return results
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            results.append({
                "host": host,
                "type": parts[0] if parts else "",
                "comment": parts[2] if len(parts) > 2 else "",
                "fingerprint": _pubkey_fingerprint(line),
            })
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as exc:
        log.error("%s: connection failed — %s", host, exc)
    return results


def deploy_key(
    host: str,
    username: str,
    password: str,
    pubkey_text: str,
    remove_fingerprint: str | None,
    port: int = 22,
) -> bool:
    """Add pubkey_text to authorized_keys; optionally remove a key by fingerprint."""
    try:
        client = _ssh_client(host, username, password, port)

        _run(client, "mkdir -p ~/.ssh && chmod 700 ~/.ssh")
        _run(client, "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")

        out, _, _ = _run(client, "cat ~/.ssh/authorized_keys")
        fingerprint_new = _pubkey_fingerprint(pubkey_text)
        existing_prints = {_pubkey_fingerprint(ln) for ln in out.splitlines() if ln.strip()}

        if fingerprint_new in existing_prints:
            log.info("%s: key already present (%s), skipping add", host, fingerprint_new[:20])
        else:
            safe = pubkey_text.replace("'", "'\\''")
            _, err, rc = _run(client, f"echo '{safe}' >> ~/.ssh/authorized_keys")
            if rc != 0:
                log.error("%s: failed to append key — %s", host, err)
                client.close()
                return False
            log.info("%s: deployed key %s", host, fingerprint_new[:20])

        if remove_fingerprint:
            lines_before = out.splitlines()
            lines_after = [
                ln for ln in lines_before
                if _pubkey_fingerprint(ln) != remove_fingerprint
            ]
            if len(lines_after) < len(lines_before):
                new_content = "\n".join(lines_after) + ("\n" if lines_after else "")
                safe_content = new_content.replace("'", "'\\''")
                _run(client, f"printf '%s' '{safe_content}' > ~/.ssh/authorized_keys")
                log.info("%s: removed key %s", host, remove_fingerprint[:20])
            else:
                log.warning("%s: fingerprint %s not found, nothing removed", host, remove_fingerprint[:20])

        client.close()
        return True
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as exc:
        log.error("%s: %s", host, exc)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Deploy or audit SSH public keys on network devices via paramiko."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("--hosts", help="File with one host per line")

    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--pubkey", help="Path to public key file to deploy")
    parser.add_argument("--remove-fingerprint", metavar="FP",
                        help="SHA256 fingerprint of key to remove during rotation")
    parser.add_argument("--audit", action="store_true",
                        help="Audit mode: list installed keys without making changes")

    args = parser.parse_args()

    if not args.audit and not args.pubkey:
        parser.error("--pubkey is required unless --audit is specified")

    hosts = [args.device] if args.device else Path(args.hosts).read_text().splitlines()
    hosts = [h.strip() for h in hosts if h.strip() and not h.startswith("#")]

    pubkey_text = ""
    if args.pubkey:
        pubkey_text = Path(args.pubkey).read_text().strip()

    success = failed = 0

    for host in hosts:
        if args.audit:
            keys = audit_keys(host, args.username, args.password, args.port)
            if keys:
                for k in keys:
                    print(f"{host}  {k['type']}  {k['fingerprint']}  {k['comment']}")
            else:
                print(f"{host}  (no keys or unreachable)")
        else:
            ok = deploy_key(
                host, args.username, args.password,
                pubkey_text, args.remove_fingerprint, args.port,
            )
            if ok:
                success += 1
            else:
                failed += 1

    if not args.audit:
        log.info("Done — %d succeeded, %d failed", success, failed)
        if failed:
            sys.exit(1)


if __name__ == "__main__":
    main()
```