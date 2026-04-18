```python
"""
bgp_neighbor_status.py - BGP Neighbor State Monitor

Purpose:
    Connects to a network device via SSH, retrieves BGP neighbor summary
    output, parses neighbor states and prefix counts, and reports any
    sessions that are not in the Established state.

Usage:
    python bgp_neighbor_status.py -d 192.168.1.1 -u admin -p secret
    python bgp_neighbor_status.py -d 10.0.0.1 -u admin --ask-pass --json
    python bgp_neighbor_status.py -d 10.0.0.1 -u admin -p secret --vrf MGMT

Prerequisites:
    pip install paramiko
    Device must support "show bgp [vrf <name>] summary" or
    "show ip bgp [vrf <name>] summary" (IOS, IOS-XE, IOS-XR, NX-OS).
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# Matches a BGP neighbor summary line:
# <neighbor-ip>  <v> <as> <msgrcvd> <msgsent> <tblver> <inq> <outq> <uptime> <prefixes|state>
_NEIGHBOR_RE = re.compile(
    r"^(?P<neighbor>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<ver>\d+)\s+"
    r"(?P<remote_as>\d+)\s+"
    r"\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+"
    r"(?P<uptime>\S+)\s+"
    r"(?P<state_pfx>\S+)",
    re.MULTILINE,
)

_LOCAL_AS_RE = re.compile(r"local AS number (\d+)", re.IGNORECASE)
_ROUTER_ID_RE = re.compile(r"BGP router identifier (\S+)", re.IGNORECASE)


@dataclass
class BgpNeighbor:
    neighbor: str
    remote_as: int
    uptime: str
    state: str
    prefixes_received: Optional[int]
    established: bool


def ssh_run(host: str, port: int, username: str, password: str,
            command: str, timeout: int = 30) -> str:
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
            log.debug("stderr from device: %s", err)
        return output
    finally:
        client.close()


def parse_bgp_summary(raw: str) -> List[BgpNeighbor]:
    neighbors: List[BgpNeighbor] = []
    for m in _NEIGHBOR_RE.finditer(raw):
        state_pfx = m.group("state_pfx")
        try:
            pfx = int(state_pfx)
            state = "Established"
            established = True
        except ValueError:
            pfx = None
            state = state_pfx
            established = False

        neighbors.append(BgpNeighbor(
            neighbor=m.group("neighbor"),
            remote_as=int(m.group("remote_as")),
            uptime=m.group("uptime"),
            state=state,
            prefixes_received=pfx,
            established=established,
        ))
    return neighbors


def build_command(vrf: Optional[str], use_ipv4_unicast: bool) -> str:
    base = "show ip bgp" if use_ipv4_unicast else "show bgp"
    if vrf:
        return f"{base} vrf {vrf} summary"
    return f"{base} summary"


def print_table(neighbors: List[BgpNeighbor], local_as: str,
                router_id: str) -> None:
    print(f"\nRouter ID : {router_id}  Local AS : {local_as}")
    print(f"{'Neighbor':<18} {'Remote AS':<12} {'Uptime':<14} "
          f"{'State/PfxRcvd':<16} {'Status'}")
    print("-" * 72)
    for n in neighbors:
        pfx_display = str(n.prefixes_received) if n.established else n.state
        status = "OK" if n.established else "DOWN"
        print(f"{n.neighbor:<18} {n.remote_as:<12} {n.uptime:<14} "
              f"{pfx_display:<16} {status}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse BGP neighbor status from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument("--ask-pass", action="store_true",
                        help="Prompt for password interactively")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", default=None, help="VRF name for BGP table lookup")
    parser.add_argument("--ipv4", action="store_true",
                        help="Use 'show ip bgp' instead of 'show bgp'")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--down-only", action="store_true",
                        help="Only report neighbors not in Established state")
    parser.add_argument("--timeout", type=int, default=30,
                        help="SSH/command timeout in seconds (default: 30)")
    args = parser.parse_args()

    if args.ask_pass:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")
    elif args.password:
        password = args.password
    else:
        log.error("Provide --password or --ask-pass.")
        return 1

    command = build_command(args.vrf, args.ipv4)
    log.info("Connecting to %s:%d as %s", args.device, args.port, args.username)
    log.info("Running: %s", command)

    try:
        raw = ssh_run(args.device, args.port, args.username, password,
                      command, args.timeout)
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection error: %s", exc)
        return 1

    neighbors = parse_bgp_summary(raw)
    if not neighbors:
        log.warning("No BGP neighbors found in output. Check VRF/command variant.")
        if args.json:
            print(json.dumps([]))
        return 0

    if args.down_only:
        neighbors = [n for n in neighbors if not n.established]

    local_as_m = _LOCAL_AS_RE.search(raw)
    router_id_m = _ROUTER_ID_RE.search(raw)
    local_as = local_as_m.group(1) if local_as_m else "unknown"
    router_id = router_id_m.group(1) if router_id_m else "unknown"

    if args.json:
        payload = {
            "device": args.device,
            "router_id": router_id,
            "local_as": local_as,
            "neighbors": [asdict(n) for n in neighbors],
        }
        print(json.dumps(payload, indent=2))
    else:
        print_table(neighbors, local_as, router_id)

    down = [n for n in neighbors if not n.established]
    if down:
        log.warning("%d neighbor(s) not Established: %s",
                    len(down), ", ".join(n.neighbor for n in down))
        return 2

    log.info("All %d neighbor(s) Established.", len(neighbors))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```