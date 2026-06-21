```python
"""
vlan_audit.py - VLAN configuration audit for Cisco IOS/IOS-XE switches

Purpose:
    Connects via SSH, collects 'show vlan brief' and 'show interfaces trunk',
    cross-references them, and reports VLANs that are isolated — defined on
    the switch but active on neither access ports nor trunk links.  Useful
    before migrations, decommissions, or periodic hygiene audits.

Usage:
    python vlan_audit.py --host 10.0.0.1 -u admin -p secret
    python vlan_audit.py --host 10.0.0.1 -u admin --key ~/.ssh/id_rsa --json
    python vlan_audit.py --host 10.0.0.1 -u admin -p secret --verbose

Prerequisites:
    pip install paramiko
    Device: Cisco IOS or IOS-XE with SSH enabled, user privilege >= 1.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def ssh_run(client, command, timeout=15):
    """Execute a single command and return decoded stdout."""
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        log.debug("stderr[%r]: %s", command, err)
    return out


def parse_vlan_brief(text):
    """Return {vlan_id: {name, status, ports[]}} from 'show vlan brief' output."""
    vlans = {}
    current = None
    pattern = re.compile(r"^(\d{1,4})\s+(\S+)\s+(active|act/lshut|act/unsup|suspended)\s*(.*)")
    for line in text.splitlines():
        m = pattern.match(line)
        if m:
            vid = int(m.group(1))
            ports = [p.strip() for p in m.group(4).split(",") if p.strip()]
            vlans[vid] = {"name": m.group(2), "status": m.group(3), "ports": ports}
            current = vid
        elif current and line.startswith("                      "):
            extra = [p.strip() for p in line.split(",") if p.strip()]
            vlans[current]["ports"].extend(extra)
    return vlans


def expand_vlans(s):
    """Expand '1-3,10,20-22' to {1,2,3,10,20,21,22}. Returns empty set for 'none'."""
    result = set()
    if not s or s.strip().lower() in ("none", "all-none"):
        return result
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                result.update(range(int(a), int(b) + 1))
            except ValueError:
                continue
        elif part.isdigit():
            result.add(int(part))
    return result


def parse_trunk_interfaces(text):
    """
    Parse 'show interfaces trunk' into:
      {intf: {native(int), allowed(set[int]), active(set[int])}}
    """
    trunks = {}
    section = None

    hdr_native = re.compile(r"^Port\s+Mode\s+Encapsulation\s+Status\s+Native")
    hdr_allowed = re.compile(r"^Port\s+Vlans allowed on trunk")
    hdr_active = re.compile(r"^Port\s+Vlans allowed and active")
    hdr_stp = re.compile(r"^Port\s+Vlans in spanning")
    data_re = re.compile(r"^(\S+)\s+(.*)")

    for line in text.splitlines():
        if hdr_native.match(line):
            section = "native"
            continue
        if hdr_allowed.match(line):
            section = "allowed"
            continue
        if hdr_active.match(line):
            section = "active"
            continue
        if hdr_stp.match(line):
            section = None
            continue

        m = data_re.match(line)
        if not m or not line[0].isalpha():
            continue

        intf, rest = m.group(1), m.group(2).strip()

        if section == "native":
            parts = rest.split()
            # format: mode  encap  status  native_vlan
            if len(parts) >= 4 and parts[2] == "trunking":
                try:
                    trunks[intf] = {
                        "native": int(parts[3]),
                        "allowed": set(),
                        "active": set(),
                    }
                except ValueError:
                    pass
        elif section == "allowed" and intf in trunks:
            trunks[intf]["allowed"] = expand_vlans(rest)
        elif section == "active" and intf in trunks:
            trunks[intf]["active"] = expand_vlans(rest)

    return trunks


def build_audit(vlans, trunks):
    """Cross-reference VLANs against trunk active sets; flag isolated ones."""
    rows = []
    for vid, info in sorted(vlans.items()):
        if vid == 1:
            continue  # skip native/management default
        active_on = [p for p, d in trunks.items() if vid in d["active"]]
        rows.append({
            "vlan": vid,
            "name": info["name"],
            "status": info["status"],
            "access_ports": info["ports"],
            "trunk_ports": active_on,
            "isolated": not active_on and not info["ports"],
        })
    return rows


def print_report(host, rows, trunks):
    print(f"\nVLAN Audit — {host}  ({len(rows)} VLANs, {len(trunks)} trunk ports)\n")
    fmt = "{:<6} {:<20} {:<10} {:<30} {:<22} {}"
    print(fmt.format("VLAN", "Name", "Status", "Trunk Ports", "Access Ports", "Flag"))
    print("-" * 98)
    for r in rows:
        tp = ", ".join(r["trunk_ports"]) or "—"
        ap = r["access_ports"]
        ap_str = ", ".join(ap[:3]) + (f" +{len(ap)-3}" if len(ap) > 3 else "") if ap else "—"
        flag = "ISOLATED" if r["isolated"] else ""
        print(fmt.format(r["vlan"], r["name"][:20], r["status"], tp[:30], ap_str[:22], flag))

    isolated = [r for r in rows if r["isolated"]]
    if isolated:
        print(f"\n[!] {len(isolated)} isolated VLAN(s) — no access or active trunk ports:")
        for r in isolated:
            print(f"    VLAN {r['vlan']:>4}  {r['name']}")
    else:
        print("\n[✓] No isolated VLANs found.")


def connect(host, port, username, password, key_file, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host, "port": port, "username": username,
        "timeout": timeout, "look_for_keys": False, "allow_agent": False,
    }
    if key_file:
        kwargs.update(key_filename=key_file, look_for_keys=True)
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def main():
    parser = argparse.ArgumentParser(
        description="Audit VLAN usage on a Cisco IOS/IOS-XE switch via SSH"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", metavar="KEYFILE", help="SSH private key path")
    parser.add_argument("--timeout", type=int, default=15, help="SSH timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of table")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        client = connect(args.host, args.port, args.username, args.password, args.key, args.timeout)
    except paramiko.AuthenticationException:
        sys.exit(f"ERROR: Authentication failed for {args.username}@{args.host}")
    except (paramiko.SSHException, OSError) as exc:
        sys.exit(f"ERROR: SSH connection failed: {exc}")

    try:
        vlan_out = ssh_run(client, "show vlan brief")
        trunk_out = ssh_run(client, "show interfaces trunk")
    finally:
        client.close()

    vlans = parse_vlan_brief(vlan_out)
    trunks = parse_trunk_interfaces(trunk_out)

    if not vlans:
        print("WARNING: No VLANs parsed — verify device type and permissions.", file=sys.stderr)

    rows = build_audit(vlans, trunks)

    if args.json:
        output = {
            "host": args.host,
            "vlans": rows,
            "trunks": {
                k: {
                    "native": v["native"],
                    "allowed_count": len(v["allowed"]),
                    "active_vlans": sorted(v["active"]),
                }
                for k, v in sorted(trunks.items())
            },
        }
        print(json.dumps(output, indent=2))
    else:
        print_report(args.host, rows, trunks)


if __name__ == "__main__":
    main()
```