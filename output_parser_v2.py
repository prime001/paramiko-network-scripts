cdp_neighbor_map.py - Cisco CDP Neighbor Discovery Parser

Purpose:
    Connects to a Cisco network device via SSH, retrieves CDP neighbor
    detail output, and parses it into structured records showing device
    identity, platform, capabilities, and link adjacency information.
    Useful for automated topology discovery and neighbor validation.

Usage:
    python cdp_neighbor_map.py -H 192.168.1.1 -u admin -p secret
    python cdp_neighbor_map.py -H 192.168.1.1 -u admin --json
    python cdp_neighbor_map.py -H 192.168.1.1 -u admin -o neighbors.json

Prerequisites:
    pip install paramiko
    Target device must have CDP enabled and SSH accessible.
    Tested against IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import getpass
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


def ssh_connect(host, username, password, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.warning("Device stderr: %s", err.strip())
    return output


def parse_cdp_neighbors(raw_output):
    neighbors = []
    blocks = re.split(r"-{10,}", raw_output)

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        m = re.search(r"Device ID:\s*(.+)", block)
        if not m:
            continue
        neighbor = {"device_id": m.group(1).strip()}

        m = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)", block)
        neighbor["ip_address"] = m.group(1) if m else "unknown"

        m = re.search(r"Platform:\s*([^,]+),", block)
        neighbor["platform"] = m.group(1).strip() if m else "unknown"

        m = re.search(r"Capabilities:\s*(.+)", block)
        neighbor["capabilities"] = m.group(1).strip() if m else ""

        m = re.search(r"Interface:\s*([^,]+),", block)
        neighbor["local_interface"] = m.group(1).strip() if m else "unknown"

        m = re.search(r"Port ID \(outgoing port\):\s*(.+)", block)
        neighbor["remote_interface"] = m.group(1).strip() if m else "unknown"

        # Grab first line of version string only
        m = re.search(r"Version\s*:\s*\n?\s*(.+)", block)
        neighbor["software_version"] = m.group(1).strip() if m else ""

        neighbors.append(neighbor)

    return neighbors


def format_table(neighbors):
    if not neighbors:
        return "No CDP neighbors found."

    headers = ["Device ID", "IP Address", "Platform", "Local Intf", "Remote Intf", "Capabilities"]
    rows = [
        [
            n.get("device_id", ""),
            n.get("ip_address", ""),
            n.get("platform", ""),
            n.get("local_interface", ""),
            n.get("remote_interface", ""),
            n.get("capabilities", ""),
        ]
        for n in neighbors
    ]

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header_row = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"

    lines = [sep, header_row, sep]
    for row in rows:
        lines.append("| " + " | ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row)) + " |")
    lines.append(sep)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Parse CDP neighbor details from a Cisco device via SSH."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")
    parser.add_argument("-o", "--output", help="Write output to file instead of stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    logger.info("Connecting to %s:%d", args.host, args.port)
    try:
        client = ssh_connect(args.host, args.username, password, port=args.port)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        logger.info("Running 'show cdp neighbors detail'")
        raw = run_command(client, "show cdp neighbors detail")
    finally:
        client.close()

    neighbors = parse_cdp_neighbors(raw)
    logger.info("Parsed %d CDP neighbor(s)", len(neighbors))

    result = json.dumps(neighbors, indent=2) if args.as_json else format_table(neighbors)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(result + "\n")
            logger.info("Output written to %s", args.output)
        except OSError as exc:
            logger.error("Failed to write output file: %s", exc)
            sys.exit(1)
    else:
        print(result)


if __name__ == "__main__":
    main()