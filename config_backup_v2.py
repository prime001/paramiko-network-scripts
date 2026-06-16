```python
"""
vlan_backup.py - Network VLAN Database Backup Tool

Purpose:
    Connects to Cisco IOS/IOS-XE network devices via SSH and extracts VLAN
    configuration and status data, saving it to structured JSON files.
    Unlike full running-config backup, this targets the VLAN database only,
    making VLAN audits, diffs, and restores faster and more focused.

Usage:
    python vlan_backup.py -H 192.168.1.1 -u admin -p secret
    python vlan_backup.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python vlan_backup.py --hosts-file devices.txt -u admin -p secret --csv

Prerequisites:
    pip install paramiko
    SSH must be enabled on target devices (read-only access sufficient).
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.

Output:
    JSON per device : {output_dir}/{host}_{timestamp}_vlans.json
    Optional CSV    : {output_dir}/vlan_summary_{timestamp}.csv
"""

import argparse
import csv
import json
import logging
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_file),
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key")
    client.connect(**kwargs)
    return client


def run_command_shell(client, command, wait=1.5, buffer=4096):
    """Use an interactive shell channel so IOS pipe (|) works correctly."""
    chan = client.invoke_shell()
    chan.settimeout(10)
    time.sleep(0.5)
    chan.recv(buffer)  # discard banner/prompt

    chan.send("terminal length 0\n")
    time.sleep(0.4)
    chan.recv(buffer)

    chan.send(command + "\n")
    time.sleep(wait)

    output = ""
    while chan.recv_ready():
        output += chan.recv(buffer).decode("utf-8", errors="replace")
        time.sleep(0.1)

    chan.close()
    return output


def parse_vlan_brief(output):
    vlans = []
    past_header = False
    for line in output.splitlines():
        if re.match(r"^-{4,}", line):
            past_header = True
            continue
        if not past_header:
            continue
        # "10   management   active    Gi1/0/1, Gi1/0/2"
        m = re.match(
            r"^(\d{1,4})\s+(\S+)\s+(active|act/lshut|act/ishut|suspend|unsup)\s*(.*)?$",
            line.strip(),
        )
        if m:
            vlan_id, name, status, ports_raw = m.groups()
            ports = [p.strip() for p in ports_raw.split(",") if p.strip()]
            vlans.append({"id": int(vlan_id), "name": name, "status": status, "ports": ports})
        elif vlans and line.strip() and not re.match(r"^\d", line.strip()):
            # Continuation: additional ports wrapped to next line
            extra = [p.strip() for p in line.split(",") if p.strip()]
            vlans[-1]["ports"].extend(extra)
    return vlans


def parse_vlan_detail(output):
    """Pull MTU values from verbose 'show vlan' output."""
    detail = {}
    current = None
    for line in output.splitlines():
        m = re.match(r"^VLAN\s+(\d+)", line)
        if m:
            current = int(m.group(1))
            detail[current] = {}
        if current:
            mtu = re.search(r"MTU\s+(\d+)", line)
            if mtu:
                detail[current]["mtu"] = int(mtu.group(1))
    return detail


def extract_hostname(output):
    m = re.search(r"hostname\s+(\S+)", output, re.IGNORECASE)
    return m.group(1) if m else None


def backup_device_vlans(host, username, password=None, key_file=None, port=22):
    log.info("Connecting to %s:%d", host, port)
    try:
        client = ssh_connect(host, username, password, key_file, port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s", host)
        return None
    except Exception as exc:
        log.error("Connection failed for %s: %s", host, exc)
        return None

    try:
        brief_out = run_command_shell(client, "show vlan brief")
        detail_out = run_command_shell(client, "show vlan")
        hostname_out = run_command_shell(client, "show running-config | include ^hostname")
    finally:
        client.close()

    vlans = parse_vlan_brief(brief_out)
    if not vlans:
        log.warning("%s: no VLAN data parsed — device may not support 'show vlan brief'", host)

    detail = parse_vlan_detail(detail_out)
    for vlan in vlans:
        if vlan["id"] in detail:
            vlan.update(detail[vlan["id"]])

    hostname = extract_hostname(hostname_out) or host

    return {
        "device": host,
        "hostname": hostname,
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "vlan_count": len(vlans),
        "vlans": vlans,
    }


def write_json(data, output_dir, host):
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^\w.-]", "_", host)
    path = output_dir / f"{safe}_{ts}_vlans.json"
    path.write_text(json.dumps(data, indent=2))
    log.info("Saved %d VLANs → %s", data["vlan_count"], path)
    return path


def write_csv_summary(all_data, output_dir):
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"vlan_summary_{ts}.csv"
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["device", "hostname", "vlan_id", "name", "status", "port_count"])
        for data in all_data:
            for vlan in data["vlans"]:
                writer.writerow([
                    data["device"], data["hostname"],
                    vlan["id"], vlan["name"], vlan["status"], len(vlan["ports"]),
                ])
    log.info("CSV summary → %s", path)


def main():
    parser = argparse.ArgumentParser(
        description="Backup VLAN database from Cisco IOS/IOS-XE devices"
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("-H", "--host", help="Device IP or hostname")
    host_group.add_argument("--hosts-file", help="File with one device per line")

    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password")
    parser.add_argument("--key", dest="key_file", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "-o", "--output-dir", default="./vlan_backups",
        help="Directory for output files (default: ./vlan_backups)",
    )
    parser.add_argument("--csv", action="store_true", help="Write a CSV summary across all devices")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        parser.error("Provide --password or --key")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.hosts_file:
        try:
            hosts = [
                ln.strip()
                for ln in Path(args.hosts_file).read_text().splitlines()
                if ln.strip() and not ln.startswith("#")
            ]
        except FileNotFoundError:
            log.error("Hosts file not found: %s", args.hosts_file)
            sys.exit(1)
    else:
        hosts = [args.host]

    results, failed = [], []
    for host in hosts:
        data = backup_device_vlans(
            host, args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
        )
        if data:
            write_json(data, output_dir, host)
            results.append(data)
        else:
            failed.append(host)

    if args.csv and results:
        write_csv_summary(results, output_dir)

    log.info("Done: %d succeeded, %d failed", len(results), len(failed))
    if failed:
        log.warning("Failed: %s", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
```