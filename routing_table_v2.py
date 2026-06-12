Here is the script content:

```python
"""
BGP Neighbor Status Checker

Connects to a Cisco IOS/IOS-XE/NX-OS device via SSH and retrieves BGP neighbor
summary information including neighbor state, uptime, and prefix counts.

Usage:
    python bgp_neighbor_status.py -d 192.168.1.1 -u admin -p secret
    python bgp_neighbor_status.py -d 192.168.1.1 -u admin --ask-pass --vrf MGMT
    python bgp_neighbor_status.py -d 192.168.1.1 -u admin -p secret --json

Prerequisites:
    pip install paramiko
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

BGP_SUMMARY_PATTERNS = {
    "neighbor": re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"\d+\s+"
        r"(\d+)\s+"
        r"\d+\s+\d+\s+\d+\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)",
        re.MULTILINE,
    ),
    "local_as": re.compile(r"local AS number (\d+)", re.IGNORECASE),
    "router_id": re.compile(r"router identifier (\S+)", re.IGNORECASE),
}


def ssh_connect(host, username, password, port=22, timeout=30):
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
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", username, host)
        raise
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection to %s failed: %s", host, exc)
        raise
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace").strip()
    if err:
        logger.debug("stderr for '%s': %s", command, err)
    return output


def parse_bgp_summary(output):
    neighbors = []
    local_as = None
    router_id = None

    m = BGP_SUMMARY_PATTERNS["local_as"].search(output)
    if m:
        local_as = m.group(1)

    m = BGP_SUMMARY_PATTERNS["router_id"].search(output)
    if m:
        router_id = m.group(1)

    for line in output.splitlines():
        line = line.strip()
        parts = line.split()
        if len(parts) < 10:
            continue
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parts[0]):
            continue

        neighbor_ip = parts[0]
        remote_as = parts[2]
        updown = parts[8]
        state_pfxrcd = parts[9]

        if state_pfxrcd.isdigit():
            state = "Established"
            prefixes_received = int(state_pfxrcd)
        else:
            state = state_pfxrcd
            prefixes_received = None

        neighbors.append(
            {
                "neighbor": neighbor_ip,
                "remote_as": remote_as,
                "updown": updown,
                "state": state,
                "prefixes_received": prefixes_received,
            }
        )

    return {
        "local_as": local_as,
        "router_id": router_id,
        "neighbors": neighbors,
    }


def format_table(data):
    header = f"{'Neighbor':<18} {'Remote AS':<12} {'State':<14} {'Up/Down':<12} {'Pfx Rcvd':<10}"
    sep = "-" * len(header)
    lines = [
        f"Local AS: {data['local_as'] or 'unknown'}  Router ID: {data['router_id'] or 'unknown'}",
        "",
        header,
        sep,
    ]
    for n in data["neighbors"]:
        pfx = str(n["prefixes_received"]) if n["prefixes_received"] is not None else "-"
        lines.append(
            f"{n['neighbor']:<18} {n['remote_as']:<12} {n['state']:<14} "
            f"{n['updown']:<12} {pfx:<10}"
        )
    if not data["neighbors"]:
        lines.append("  (no BGP neighbors found)")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Retrieve and display BGP neighbor summary from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", help="VRF name for BGP summary")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    parser.add_argument(
        "--json", action="store_true", dest="output_json",
        help="Output results as JSON",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or not password:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    command = "show bgp summary"
    if args.vrf:
        command = f"show bgp vrf {args.vrf} summary"

    try:
        client = ssh_connect(
            args.device, args.username, password,
            port=args.port, timeout=args.timeout,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        output = run_command(client, command, timeout=args.timeout)
    finally:
        client.close()

    data = parse_bgp_summary(output)
    data["device"] = args.device

    if args.output_json:
        print(json.dumps(data, indent=2))
    else:
        print(format_table(data))


if __name__ == "__main__":
    main()
```

This is a BGP neighbor status checker — distinct from the existing `routing_table.py` scripts. It SSHes to a device, runs `show bgp summary` (with optional VRF support), parses the neighbor table into structured data, and renders either a formatted ASCII table or JSON output. Key design points: `AutoAddPolicy` for lab use, `look_for_keys=False` to avoid accidental key auth, regex parsing of the standard IOS/IOS-XE BGP summary line format, and `--json` flag for pipeline integration.