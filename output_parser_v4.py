The request asks for the script content as output only. Here it is:

```
"""
neighbor_discovery.py - CDP/LLDP Neighbor Discovery via SSH
```

Wait — the instruction says output ONLY the script, no fences. Let me output it cleanly:

---

"""
neighbor_discovery.py - CDP/LLDP Neighbor Discovery via SSH

Purpose:
    Connects to a network device via SSH, queries CDP or LLDP neighbor detail
    output, and parses it into a structured summary of directly attached neighbors.
    Useful for topology mapping, change validation, and network audits.

Usage:
    python neighbor_discovery.py -d 192.168.1.1 -u admin
    python neighbor_discovery.py -d 192.168.1.1 -u admin --protocol lldp --json
    python neighbor_discovery.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa --protocol both

Prerequisites:
    pip install paramiko
    SSH access to device; CDP or LLDP must be enabled.
"""

import argparse
import getpass
import json
import logging
import re
import sys

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)


def ssh_connect(host, username, password=None, key_file=None, port=22, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": key_file is None,
        "allow_agent": key_file is None,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    if password:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        log.debug("stderr: %s", err.strip())
    return out


def parse_cdp_neighbors(output):
    neighbors = []
    for block in re.split(r"-{10,}", output):
        if not block.strip():
            continue
        n = {}
        for pattern, key in [
            (r"Device ID:\s*(.+)", "device_id"),
            (r"(?:IP address|IPv4 Address):\s*(\S+)", "ip_address"),
            (r"Platform:\s*([^,]+)", "platform"),
            (r"Capabilities:\s*(.+)", "capabilities"),
            (r"Interface:\s*(\S+)", "local_interface"),
            (r"Port ID \(outgoing port\):\s*(\S+)", "remote_interface"),
        ]:
            m = re.search(pattern, block, re.IGNORECASE)
            if m:
                n[key] = m.group(1).strip().rstrip(",")
        if "device_id" in n:
            neighbors.append(n)
    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    for block in re.split(r"-{10,}", output):
        if not block.strip():
            continue
        n = {}
        for pattern, key in [
            (r"System Name:\s*(.+)", "device_id"),
            (r"Management Address(?:es)?.*?IP:\s*(\S+)", "ip_address"),
            (r"System Capabilities:\s*(.+)", "capabilities"),
            (r"Local Intf:\s*(\S+)", "local_interface"),
            (r"Port id:\s*(\S+)", "remote_interface"),
        ]:
            m = re.search(pattern, block, re.IGNORECASE | re.DOTALL)
            if m:
                n[key] = m.group(1).strip()
        m = re.search(r"System Description:\s*\n(.+?)(?:\n\s*\n|\Z)", block, re.DOTALL)
        if m:
            n["platform"] = " ".join(m.group(1).split()[:8])
        if "device_id" in n:
            neighbors.append(n)
    return neighbors


def print_table(neighbors, protocol):
    if not neighbors:
        print(f"\nNo {protocol.upper()} neighbors found.")
        return

    cols = ["device_id", "local_interface", "remote_interface", "ip_address", "platform", "capabilities"]
    headers = ["Device ID", "Local Intf", "Remote Intf", "IP Address", "Platform", "Capabilities"]
    truncate = {"platform": 28, "capabilities": 22}

    widths = []
    for col, hdr in zip(cols, headers):
        vals = [str(n.get(col, ""))[:truncate.get(col, 999)] for n in neighbors]
        widths.append(max(len(hdr), max((len(v) for v in vals), default=0)))

    hdr_line = "  ".join(f"{h:<{w}}" for h, w in zip(headers, widths))
    sep = "  ".join("-" * w for w in widths)
    print(f"\n{protocol.upper()} Neighbors — {len(neighbors)} found")
    print(hdr_line)
    print(sep)
    for n in neighbors:
        row = "  ".join(
            f"{str(n.get(col, ''))[:truncate.get(col, 999)]:<{w}}"
            for col, w in zip(cols, widths)
        )
        print(row)


def main():
    parser = argparse.ArgumentParser(description="Discover CDP/LLDP neighbors on a network device via SSH.")
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted and no key)")
    parser.add_argument("-k", "--key-file", dest="key_file", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--protocol", choices=["cdp", "lldp", "both"], default="cdp",
                        help="Discovery protocol (default: cdp)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--timeout", type=int, default=30, help="Command timeout seconds (default: 30)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if not password and not args.key_file:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    log.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(args.device, args.username, password, args.key_file, args.port)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    protocols = ["cdp", "lldp"] if args.protocol == "both" else [args.protocol]
    parsers = {"cdp": ("show cdp neighbors detail", parse_cdp_neighbors),
               "lldp": ("show lldp neighbors detail", parse_lldp_neighbors)}
    results = {}

    try:
        for proto in protocols:
            cmd, parse_fn = parsers[proto]
            log.info("Running: %s", cmd)
            output = run_command(client, cmd, timeout=args.timeout)
            neighbors = parse_fn(output)
            log.info("Parsed %d %s neighbor(s)", len(neighbors), proto.upper())
            results[proto] = neighbors
    finally:
        client.close()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for proto, neighbors in results.items():
            print_table(neighbors, proto)


if __name__ == "__main__":
    main()