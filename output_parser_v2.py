bgp_summary.py — BGP Neighbor Summary Parser

Purpose:
    Connects to a Cisco IOS/IOS-XE router via SSH, retrieves BGP neighbor
    summary output, and parses it into structured data. Surfaces session
    state, prefix counts, uptime, and message counters in a compact table
    or as JSON for downstream scripting.

Usage:
    python bgp_summary.py -H 10.0.0.1 -u admin -p secret
    python bgp_summary.py -H 10.0.0.1 -u admin -p secret --vrf MGMT
    python bgp_summary.py -H 10.0.0.1 -u admin -p secret --json

Prerequisites:
    pip install paramiko
    SSH enabled on target device; account needs privilege for
    'show ip bgp summary' (enable level 5 or equivalent).
"""

import argparse
import json
import logging
import re
import sys

import paramiko

LOG = logging.getLogger(__name__)

# Matches a neighbor data line from "show ip bgp summary".
# Columns: neighbor ver ASN msgrcvd msgsent tblver inq outq uptime state/pfxrcd
_NEIGHBOR_RE = re.compile(
    r"^(?P<neighbor>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<ver>\d+)\s+"
    r"(?P<asn>\d+)\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<tbl_ver>\d+)\s+"
    r"(?P<inq>\d+)\s+"
    r"(?P<outq>\d+)\s+"
    r"(?P<uptime>\S+)\s+"
    r"(?P<state_pfxrcd>\S+)"
)
_ROUTER_ID_RE = re.compile(r"BGP router identifier (\S+?),", re.IGNORECASE)
_LOCAL_AS_RE = re.compile(r"local AS number (\d+)", re.IGNORECASE)


def ssh_run(host, port, username, password, command, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            LOG.warning("Device stderr: %s", err)
        return output
    finally:
        client.close()


def parse_bgp_summary(raw):
    router_id = None
    local_as = None
    neighbors = []

    for line in raw.splitlines():
        m = _ROUTER_ID_RE.search(line)
        if m:
            router_id = m.group(1)

        m = _LOCAL_AS_RE.search(line)
        if m:
            local_as = m.group(1)

        m = _NEIGHBOR_RE.match(line.strip())
        if not m:
            continue

        raw_state = m.group("state_pfxrcd")
        if raw_state.isdigit():
            state = "Established"
            prefixes = int(raw_state)
        else:
            # Idle, Active, Connect, OpenSent, OpenConfirm, or "(policy)"
            state = raw_state
            prefixes = None

        neighbors.append({
            "neighbor": m.group("neighbor"),
            "remote_as": m.group("asn"),
            "uptime": m.group("uptime"),
            "state": state,
            "prefixes_received": prefixes,
            "msg_rcvd": int(m.group("msg_rcvd")),
            "msg_sent": int(m.group("msg_sent")),
        })

    return {"router_id": router_id, "local_as": local_as, "neighbors": neighbors}


def render_table(data):
    print(f"Router ID : {data['router_id'] or 'unknown'}")
    print(f"Local AS  : {data['local_as'] or 'unknown'}")

    neighbors = data["neighbors"]
    if not neighbors:
        print("\nNo BGP neighbors found.")
        return

    print()
    hdr = (
        f"{'Neighbor':<18} {'Remote AS':<11} {'State':<14}"
        f" {'Pfx Rcvd':>9} {'Uptime':<12} {'MsgRcvd':>9} {'MsgSent':>9}"
    )
    print(hdr)
    print("-" * len(hdr))

    for n in neighbors:
        pfx = str(n["prefixes_received"]) if n["prefixes_received"] is not None else "-"
        print(
            f"{n['neighbor']:<18} {n['remote_as']:<11} {n['state']:<14}"
            f" {pfx:>9} {n['uptime']:<12} {n['msg_rcvd']:>9} {n['msg_sent']:>9}"
        )

    up = sum(1 for n in neighbors if n["state"] == "Established")
    print(f"\n{up}/{len(neighbors)} sessions Established")


def main():
    parser = argparse.ArgumentParser(
        description="Retrieve and parse BGP neighbor summary from a Cisco IOS/IOS-XE device."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", metavar="NAME", help="Query a VRF-specific BGP table")
    parser.add_argument(
        "--json", dest="output_json", action="store_true",
        help="Emit structured JSON instead of a human-readable table"
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="SSH connection timeout in seconds"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    cmd = (
        f"show bgp vpnv4 unicast vrf {args.vrf} summary"
        if args.vrf
        else "show ip bgp summary"
    )
    LOG.debug("Connecting to %s:%d, command: %s", args.host, args.port, cmd)

    try:
        raw = ssh_run(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            command=cmd,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        LOG.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        LOG.error("Connection failed: %s", exc)
        sys.exit(1)

    data = parse_bgp_summary(raw)

    if args.output_json:
        print(json.dumps(data, indent=2))
    else:
        render_table(data)


if __name__ == "__main__":
    main()