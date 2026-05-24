The prompt specifies the output directory isn't `/opt/NetAutoCommitter` — this is just a generation task. Writing the script now.

```python
"""vlan_inventory.py - Collect VLAN membership data from Cisco switches via SSH.

Purpose:
    Connects to a Cisco IOS/IOS-XE switch over SSH using Paramiko and retrieves
    VLAN table data (VLAN ID, name, status, assigned ports). Useful for auditing
    segmentation, documenting port assignments, and detecting stale VLANs.

Usage:
    python vlan_inventory.py -H 192.168.1.1 -u admin -p secret
    python vlan_inventory.py -H 192.168.1.1 -u admin -p secret --format csv
    python vlan_inventory.py -H 192.168.1.1 -u admin -p secret --format json -o vlans.json
    python vlan_inventory.py -H 192.168.1.1 -u admin -p secret --active-only

Prerequisites:
    pip install paramiko
    SSH must be enabled on the target device.
    Account requires at minimum privilege level 1 (show commands).
"""

import argparse
import csv
import io
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def ssh_connect(host, username, password, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        logger.info("Connected to %s:%d", host, port)
        return client
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        raise
    except paramiko.SSHException as exc:
        logger.error("SSH error connecting to %s: %s", host, exc)
        raise
    except OSError as exc:
        logger.error("Network error connecting to %s: %s", host, exc)
        raise


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.debug("stderr: %s", err.strip())
    return output


def parse_vlan_brief(output):
    """Parse 'show vlan brief' into a list of dicts."""
    vlans = []
    current = None
    past_header = False

    for line in output.splitlines():
        # The dashes line marks the end of the column headers
        if re.match(r"^-{4,}", line):
            past_header = True
            continue
        if not past_header or not line.strip():
            continue

        # Primary VLAN line: ID  Name  Status  Ports...
        m = re.match(
            r"^(\d+)\s+(\S+)\s+(active|act/unsup|suspended|act/lshut)\s*(.*)",
            line,
        )
        if m:
            vlan_id, name, status, ports_raw = m.groups()
            ports = [p.strip() for p in ports_raw.split(",") if p.strip()]
            current = {
                "vlan_id": int(vlan_id),
                "name": name,
                "status": status,
                "ports": ports,
            }
            vlans.append(current)
        elif current and re.match(r"^\s{10,}", line):
            # Continuation line: additional ports for the previous VLAN
            extra = [p.strip() for p in line.split(",") if p.strip()]
            current["ports"].extend(extra)

    return vlans


def render_table(vlans):
    if not vlans:
        return "No VLANs found."
    header = f"{'VLAN':<6}  {'Name':<32}  {'Status':<12}  Ports"
    sep = "-" * 90
    lines = [header, sep]
    for v in vlans:
        ports = ", ".join(v["ports"]) if v["ports"] else "(unassigned)"
        lines.append(f"{v['vlan_id']:<6}  {v['name']:<32}  {v['status']:<12}  {ports}")
    return "\n".join(lines)


def render_csv(vlans):
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=["vlan_id", "name", "status", "ports"], extrasaction="ignore"
    )
    writer.writeheader()
    for v in vlans:
        writer.writerow({**v, "ports": ", ".join(v["ports"])})
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser(
        description="Collect VLAN inventory from a Cisco IOS/IOS-XE switch via SSH."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--format",
        choices=["table", "csv", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--active-only",
        action="store_true",
        help="Exclude suspended/unsupported VLANs",
    )
    parser.add_argument("-o", "--output", help="Write output to file instead of stdout")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Command timeout in seconds (default: 30)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        client = ssh_connect(args.host, args.username, args.password, args.port)
    except Exception:
        sys.exit(1)

    try:
        logger.info("Running 'show vlan brief' on %s", args.host)
        raw = run_command(client, "show vlan brief", timeout=args.timeout)
    finally:
        client.close()

    vlans = parse_vlan_brief(raw)

    if args.active_only:
        vlans = [v for v in vlans if v["status"] == "active"]

    logger.info("Found %d VLAN(s)", len(vlans))

    if args.format == "table":
        result = render_table(vlans)
    elif args.format == "csv":
        result = render_csv(vlans)
    else:
        result = json.dumps(vlans, indent=2)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(result)
        logger.info("Output written to %s", args.output)
    else:
        print(result)


if __name__ == "__main__":
    main()
```