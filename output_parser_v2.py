The prompt asks for script content output only — here it is:

```
"""
vlan_audit.py - VLAN table auditor for Cisco IOS/IOS-XE devices

Connects via SSH (paramiko), runs 'show vlan brief', parses the output into
structured records, and exports as a console table, JSON, or CSV.  Useful for
VLAN inventory audits, change verification, and drift detection.

Usage:
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --format csv -o vlans.csv
    python vlan_audit.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa --active-only
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --format json -o vlans.json

Prerequisites:
    pip install paramiko
"""
```

Since I can't write to `/opt/NetAutoCommitter`, here is the raw script content (no fences, no explanation — copy this directly):

---

"""
vlan_audit.py - VLAN table auditor for Cisco IOS/IOS-XE devices

Connects via SSH (paramiko), runs 'show vlan brief', parses the output into
structured records, and exports as a console table, JSON, or CSV.  Useful for
VLAN inventory audits, change verification, and drift detection.

Usage:
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --format csv -o vlans.csv
    python vlan_audit.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa --active-only
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --format json -o vlans.json

Prerequisites:
    pip install paramiko
"""

import argparse
import csv
import json
import logging
import re
import sys
import time

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def connect(host, username, password=None, key_path=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=bool(key_path),
        allow_agent=False,
    )
    if key_path:
        kwargs["key_filename"] = key_path
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key")
    client.connect(**kwargs)
    return client


def run_command(client, command, settle=1.5):
    shell = client.invoke_shell()
    shell.settimeout(10)
    time.sleep(0.4)
    if shell.recv_ready():
        shell.recv(8192)
    shell.send("terminal length 0\n")
    time.sleep(0.3)
    if shell.recv_ready():
        shell.recv(8192)
    shell.send(command + "\n")
    time.sleep(settle)
    output = ""
    while shell.recv_ready():
        output += shell.recv(8192).decode("utf-8", errors="replace")
        time.sleep(0.15)
    shell.close()
    return output


def parse_vlan_brief(raw):
    """Return list of dicts from 'show vlan brief' output."""
    vlans = []
    past_header = False
    status_pat = re.compile(
        r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|act/lshut|suspended|unsupported)\s*(.*)?$",
        re.IGNORECASE,
    )
    for line in raw.splitlines():
        stripped = line.strip()
        if re.match(r"^-{4,}", stripped):
            past_header = True
            continue
        if not past_header or not stripped:
            continue
        m = status_pat.match(stripped)
        if m:
            ports = [p.strip() for p in m.group(4).split(",") if p.strip()]
            vlans.append({
                "vlan_id": int(m.group(1)),
                "name": m.group(2),
                "status": m.group(3).lower(),
                "port_count": len(ports),
                "ports": ", ".join(ports),
            })
        elif vlans and re.match(r"^[A-Za-z]{2}\d", stripped):
            extra = [p.strip() for p in stripped.split(",") if p.strip()]
            vlans[-1]["ports"] += (", " if vlans[-1]["ports"] else "") + ", ".join(extra)
            vlans[-1]["port_count"] += len(extra)
    return vlans


def print_table(vlans):
    if not vlans:
        print("No VLANs found.")
        return
    print(f"{'VLAN':>6}  {'Name':<28}  {'Status':<14}  {'Ports':>5}  Interfaces")
    print("-" * 82)
    for v in vlans:
        preview = (v["ports"][:33] + "…") if len(v["ports"]) > 34 else v["ports"]
        print(f"{v['vlan_id']:>6}  {v['name']:<28}  {v['status']:<14}  {v['port_count']:>5}  {preview}")
    print(f"\nTotal: {len(vlans)} VLANs")


def export_json(vlans, outfile=None):
    data = json.dumps(vlans, indent=2)
    if outfile:
        with open(outfile, "w") as fh:
            fh.write(data)
        log.info("Wrote JSON → %s", outfile)
    else:
        print(data)


def export_csv(vlans, outfile=None):
    fields = ["vlan_id", "name", "status", "port_count", "ports"]
    dest = open(outfile, "w", newline="") if outfile else sys.stdout
    try:
        writer = csv.DictWriter(dest, fieldnames=fields)
        writer.writeheader()
        writer.writerows(vlans)
    finally:
        if outfile:
            dest.close()
            log.info("Wrote CSV → %s", outfile)


def build_parser():
    p = argparse.ArgumentParser(
        description="Audit VLAN table on a Cisco IOS device via SSH"
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--key", metavar="FILE", help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    p.add_argument(
        "--format", choices=["table", "json", "csv"], default="table",
        help="Output format (default: table)",
    )
    p.add_argument("-o", "--output", metavar="FILE", help="Write output to file")
    p.add_argument(
        "--active-only", action="store_true",
        help="Include only VLANs with status 'active'",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main():
    args = build_parser().parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if not args.password and not args.key:
        sys.exit("error: provide --password or --key")

    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    try:
        client = connect(
            args.device, args.username,
            password=args.password, key_path=args.key, port=args.port,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed")
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        log.info("Running 'show vlan brief'")
        raw = run_command(client, "show vlan brief")
        log.debug("Raw output:\n%s", raw)
    finally:
        client.close()

    vlans = parse_vlan_brief(raw)
    if not vlans:
        log.error("No VLAN records parsed — verify device output format")
        sys.exit(1)

    if args.active_only:
        vlans = [v for v in vlans if v["status"] == "active"]

    log.info("Parsed %d VLANs", len(vlans))

    if args.format == "json":
        export_json(vlans, args.output)
    elif args.format == "csv":
        export_csv(vlans, args.output)
    else:
        print_table(vlans)
        if args.output:
            export_json(vlans, args.output)


if __name__ == "__main__":
    main()