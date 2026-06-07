BGP Summary Parser

Purpose:
    Connects to a network device via SSH and parses 'show ip bgp summary' (or
    equivalent) output into structured data. Reports neighbor states, prefixes
    received, uptime, and flags any sessions that are not Established.

Usage:
    python bgp_summary_parser.py -H 192.168.1.1 -u admin -p secret
    python bgp_summary_parser.py -H 10.0.0.1 -u admin --key ~/.ssh/id_rsa --afi ipv6
    python bgp_summary_parser.py -H 10.0.0.1 -u admin -p secret --warn-only

Prerequisites:
    pip install paramiko
    SSH access to the target device with show-level privileges.
    Tested against Cisco IOS, IOS-XE, and NX-OS output formats.
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

import paramiko

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
log = logging.getLogger(__name__)


@dataclass
class BgpNeighbor:
    neighbor: str
    as_number: str
    msg_rcvd: str
    msg_sent: str
    uptime: str
    state_prefixes: str
    established: bool


def ssh_run(host: str, port: int, username: str, password: Optional[str],
            key_path: Optional[str], command: str, timeout: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict = dict(
        hostname=host, port=port, username=username,
        timeout=timeout, look_for_keys=False, allow_agent=False,
    )
    if key_path:
        connect_kwargs["key_filename"] = key_path
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("Provide --password or --key")

    try:
        client.connect(**connect_kwargs)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.debug("stderr: %s", err)
        return output
    finally:
        client.close()


def parse_bgp_summary(output: str) -> List[BgpNeighbor]:
    """Parse IOS/IOS-XE/NX-OS tabular BGP summary output."""
    neighbors = []
    in_table = False
    header_re = re.compile(r"Neighbor\s+V\s+AS\b", re.IGNORECASE)
    row_re = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+"  # neighbor IP (v4 or v6)
        r"\d+\s+"                                           # BGP version
        r"(\d+)\s+"                                         # remote AS
        r"(\d+)\s+"                                         # MsgRcvd
        r"(\d+)\s+"                                         # MsgSent
        r"\S+\s+"                                           # TblVer
        r"\S+\s+"                                           # InQ
        r"\S+\s+"                                           # OutQ
        r"(\S+)\s+"                                         # Up/Down
        r"(\S+)"                                            # State/PfxRcd
    )
    for line in output.splitlines():
        if header_re.search(line):
            in_table = True
            continue
        if not in_table:
            continue
        m = row_re.match(line.strip())
        if not m:
            continue
        neighbor, asn, msg_rcvd, msg_sent, uptime, state = m.groups()
        try:
            pfx = int(state)
            established = True
            label = f"{pfx} pfx"
        except ValueError:
            established = False
            label = state
        neighbors.append(BgpNeighbor(
            neighbor=neighbor, as_number=asn, msg_rcvd=msg_rcvd,
            msg_sent=msg_sent, uptime=uptime,
            state_prefixes=label, established=established,
        ))
    return neighbors


def extract_local_as(output: str) -> str:
    m = re.search(r"local AS number\s+(\d+)", output, re.IGNORECASE)
    if not m:
        m = re.search(r"BGP router identifier[^,]*,\s*local AS number\s+(\d+)", output, re.IGNORECASE)
    return m.group(1) if m else ""


def print_table(neighbors: List[BgpNeighbor], local_as: str) -> None:
    if local_as:
        print(f"Local AS: {local_as}")
    print()
    hdr = "{:<22} {:<8} {:<10} {:<10} {:<13} {}"
    print(hdr.format("Neighbor", "AS", "MsgRcvd", "MsgSent", "Uptime", "State/Pfx"))
    print("-" * 72)
    for n in neighbors:
        label = n.state_prefixes if n.established else f"[{n.state_prefixes}]"
        print(hdr.format(n.neighbor, n.as_number, n.msg_rcvd, n.msg_sent, n.uptime, label))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Parse BGP summary output from a network device.")
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--key", dest="key_path", default=None, help="SSH private key path")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--afi", choices=["ipv4", "ipv6", "vpnv4"], default="ipv4",
                   help="Address family to query (default: ipv4)")
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout seconds (default: 30)")
    p.add_argument("--warn-only", action="store_true",
                   help="Exit 0 even when non-Established sessions exist")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    if not args.password and not args.key_path:
        print("ERROR: provide --password or --key", file=sys.stderr)
        return 2

    commands = {
        "ipv4": "show ip bgp summary",
        "ipv6": "show bgp ipv6 unicast summary",
        "vpnv4": "show bgp vpnv4 unicast all summary",
    }

    print(f"Connecting to {args.host}:{args.port} ...")
    try:
        output = ssh_run(
            host=args.host, port=args.port, username=args.username,
            password=args.password, key_path=args.key_path,
            command=commands[args.afi], timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        print("ERROR: Authentication failed", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    log.debug("Raw output:\n%s", output)

    if not output.strip():
        print("ERROR: empty response from device", file=sys.stderr)
        return 1

    local_as = extract_local_as(output)
    neighbors = parse_bgp_summary(output)

    if not neighbors:
        print("No BGP neighbors parsed. Raw output:")
        print(output)
        return 0

    print_table(neighbors, local_as)

    down = [n for n in neighbors if not n.established]
    print(f"\nSummary: {len(neighbors) - len(down)}/{len(neighbors)} neighbors Established")

    if down:
        print("\nNon-Established sessions:")
        for n in down:
            print(f"  {n.neighbor:<22} AS {n.as_number:<8} state={n.state_prefixes}")
        if not args.warn_only:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())