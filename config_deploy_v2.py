Writing a VLAN audit and provisioning script — distinct from all existing scripts in the repo.

```python
#!/usr/bin/env python3
"""
vlan_audit.py - VLAN database audit and provisioning for Cisco IOS switches

Purpose:
    Query the VLAN database and port assignments on a Cisco IOS switch via SSH.
    Optionally verify that required VLANs are present and provision any missing ones.

Usage:
    # Audit only
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret

    # Verify specific VLANs are present
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret --required-vlans 10,20,30

    # Provision missing VLANs (requires enable secret for privilege 15)
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret \
        --required-vlans 10,20,30 --provision --enable-secret cisco \
        --vlan-names "10=mgmt,20=voice,30=data"

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Read-only access suffices for audit; privilege 15 required for --provision.
"""

import argparse
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def _connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return client


def _open_shell(client: paramiko.SSHClient) -> paramiko.Channel:
    shell = client.invoke_shell(width=220, height=50)
    shell.settimeout(10)
    time.sleep(1)
    _drain(shell)
    return shell


def _drain(shell: paramiko.Channel) -> str:
    buf = ""
    try:
        while shell.recv_ready():
            buf += shell.recv(4096).decode("utf-8", errors="replace")
    except Exception:
        pass
    return buf


def _send(shell: paramiko.Channel, cmd: str, wait: float = 1.5) -> str:
    shell.send(cmd + "\n")
    time.sleep(wait)
    output = ""
    for _ in range(20):
        chunk = _drain(shell)
        output += chunk
        if re.search(r"[#>]\s*$", output):
            break
        time.sleep(0.3)
    return output


def _enter_enable(shell: paramiko.Channel, secret: str) -> None:
    out = _send(shell, "enable", wait=1.0)
    if "Password" in out:
        _send(shell, secret, wait=1.0)


def _parse_vlan_brief(output: str) -> dict:
    """Return {vlan_id: {'name': str, 'status': str, 'ports': list}}."""
    vlans = {}
    current = None
    for line in output.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+(active|act/unsup|suspended)\s*(.*)?$", line)
        if m:
            vid = int(m.group(1))
            ports = [p.strip() for p in m.group(4).split(",") if p.strip()]
            vlans[vid] = {"name": m.group(2), "status": m.group(3), "ports": ports}
            current = vid
        elif current and re.match(r"^\s{20,}", line):
            vlans[current]["ports"].extend(
                p.strip() for p in line.split(",") if p.strip()
            )
    return vlans


def _parse_trunk_ports(output: str) -> list:
    trunks = []
    capture = False
    for line in output.splitlines():
        if re.match(r"^Port\s+Mode\s+Encapsulation", line):
            capture = True
            continue
        if capture:
            if not line.strip() or line.startswith("Port"):
                capture = False
                continue
            m = re.match(r"^(\S+)\s+", line)
            if m:
                trunks.append(m.group(1))
    return trunks


def _provision(
    shell: paramiko.Channel, missing: list, names: dict
) -> None:
    log.info("Entering config mode to provision %d VLAN(s)", len(missing))
    _send(shell, "configure terminal", wait=1.0)
    for vid in missing:
        _send(shell, f"vlan {vid}", wait=0.5)
        if vid in names:
            _send(shell, f" name {names[vid]}", wait=0.3)
        _send(shell, "exit", wait=0.3)
        log.info("  Provisioned VLAN %d", vid)
    _send(shell, "end", wait=0.5)
    _send(shell, "write memory", wait=3.0)
    log.info("Configuration saved")


def main() -> int:
    p = argparse.ArgumentParser(
        description="Audit and optionally provision VLANs on Cisco IOS switches"
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--required-vlans",
        help="Comma-separated VLAN IDs to verify (e.g. 10,20,30)",
    )
    p.add_argument(
        "--provision",
        action="store_true",
        help="Create any missing VLANs (requires --required-vlans)",
    )
    p.add_argument("--enable-secret", default="", help="Enable secret for privilege 15")
    p.add_argument(
        "--vlan-names",
        help="Name map for provisioning: '10=mgmt,20=voice'",
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.getLogger().setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logging.getLogger("paramiko").setLevel(
        logging.DEBUG if args.verbose else logging.WARNING
    )

    required = []
    if args.required_vlans:
        try:
            required = [int(v.strip()) for v in args.required_vlans.split(",")]
        except ValueError:
            log.error("--required-vlans must be comma-separated integers")
            return 1

    vlan_names = {}
    if args.vlan_names:
        for pair in args.vlan_names.split(","):
            if "=" in pair:
                vid, name = pair.split("=", 1)
                vlan_names[int(vid.strip())] = name.strip()

    log.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = _connect(args.host, args.port, args.username, args.password)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for user '%s'", args.username)
        return 1
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        return 1

    try:
        shell = _open_shell(client)
        if args.provision and args.enable_secret:
            _enter_enable(shell, args.enable_secret)
        _send(shell, "terminal length 0", wait=0.5)

        vlans = _parse_vlan_brief(_send(shell, "show vlan brief", wait=2.0))
        trunks = _parse_trunk_ports(_send(shell, "show interfaces trunk", wait=2.0))

        print(f"\n{'='*62}")
        print(f"VLAN Audit — {args.host}")
        print(f"{'='*62}")
        print(f"{'ID':<6} {'Name':<20} {'Status':<12} Ports")
        print(f"{'-'*6} {'-'*20} {'-'*12} {'-'*20}")
        for vid in sorted(vlans):
            v = vlans[vid]
            ports_str = ", ".join(v["ports"][:4])
            if len(v["ports"]) > 4:
                ports_str += f" (+{len(v['ports']) - 4} more)"
            print(f"{vid:<6} {v['name']:<20} {v['status']:<12} {ports_str}")

        print(f"\nTrunk ports: {', '.join(trunks) if trunks else 'none detected'}")
        print(f"Total VLANs: {len(vlans)}")

        if required:
            existing = set(vlans)
            missing = [v for v in required if v not in existing]
            present = [v for v in required if v in existing]
            print(f"\nRequired VLAN check ({len(required)} VLANs):")
            for vid in present:
                print(f"  [OK]      VLAN {vid} — {vlans[vid]['name']}")
            for vid in missing:
                print(f"  [MISSING] VLAN {vid}")
            if missing and args.provision:
                _provision(shell, missing, vlan_names)
                print(f"\nProvisioned: {missing}")
            elif missing:
                print(f"\n{len(missing)} VLAN(s) missing. Add --provision to create them.")

        print()
        return 0

    except Exception as exc:
        log.error("Audit failed: %s", exc)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
```