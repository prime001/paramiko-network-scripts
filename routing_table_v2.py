#!/usr/bin/env python3
"""
bgp_monitor.py - BGP peer session health monitor for Cisco IOS/IOS-XE devices.

Purpose:
    Connects via SSH and retrieves BGP summary data, reporting each peer's
    session state, prefix counts, and session uptime. Flags any peer not in
    Established state and exits non-zero so it integrates cleanly with monitoring
    scripts or CI health checks.

Usage:
    python bgp_monitor.py -d 192.168.1.1 -u admin -p secret
    python bgp_monitor.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python bgp_monitor.py -d 192.168.1.1 -u admin -p secret --vrf MGMT
    python bgp_monitor.py -d 192.168.1.1 -u admin -p secret --ipv6

Prerequisites:
    pip install paramiko
    SSH must be enabled on the device and BGP must be configured.

Exit codes:
    0 - All peers Established
    1 - One or more peers not Established, or connection/auth failure
    2 - BGP not configured or no peers detected
"""

import argparse
import getpass
import logging
import re
import sys

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
        "look_for_keys": False,
        "allow_agent": False,
    }
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=20):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        log.debug("stderr: %s", err.strip())
    return output


def parse_bgp_summary(output):
    """
    Parse IOS/IOS-XE 'show [ip] bgp summary' output into structured peer data.
    The State/PfxRcd column holds an integer when Established, otherwise a
    state keyword (Idle, Active, Connect, OpenSent, OpenConfirm).
    """
    peers = []
    peer_re = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+"
        r"\d+\s+"
        r"(\d+)\s+"
        r"\d+\s+"
        r"(\d+)\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"\d+\s+"
        r"(\S+)\s+"
        r"(\S+)$",
        re.MULTILINE,
    )
    local_as_m = re.search(r"local AS number (\d+)", output, re.IGNORECASE)
    router_id_m = re.search(r"BGP router identifier (\S+)", output, re.IGNORECASE)

    for m in peer_re.finditer(output):
        neighbor, remote_as, msg_sent, updown, state_field = m.groups()
        try:
            pfx_rcvd = int(state_field)
            state = "Established"
        except ValueError:
            pfx_rcvd = 0
            state = state_field

        peers.append({
            "neighbor": neighbor,
            "remote_as": remote_as,
            "updown": updown,
            "state": state,
            "pfx_rcvd": pfx_rcvd,
        })

    return {
        "router_id": router_id_m.group(1) if router_id_m else "unknown",
        "local_as": local_as_m.group(1) if local_as_m else "unknown",
        "peers": peers,
    }


def print_report(data, host):
    peers = data["peers"]
    print(f"\nBGP Summary — {host}")
    print(f"  Router ID : {data['router_id']}   Local AS: {data['local_as']}")
    print(f"  Peers     : {len(peers)} total\n")

    col = "{:<22} {:<10} {:<16} {:<14} {:<10}"
    header = col.format("Neighbor", "AS", "Up/Down", "State", "PfxRcvd")
    print(header)
    print("-" * 72)

    for p in peers:
        flag = "  " if p["state"] == "Established" else "! "
        print(flag + col.format(
            p["neighbor"], p["remote_as"], p["updown"], p["state"], p["pfx_rcvd"]
        ))

    print()
    not_up = [p for p in peers if p["state"] != "Established"]
    if not_up:
        log.warning("%d peer(s) not in Established state:", len(not_up))
        for p in not_up:
            log.warning("  ! %s (AS %s) state=%s updown=%s",
                        p["neighbor"], p["remote_as"], p["state"], p["updown"])
        return False

    log.info("All %d BGP peer(s) Established.", len(peers))
    return True


def build_command(args):
    if args.ipv6:
        return "show bgp ipv6 unicast summary"
    if args.vrf:
        return f"show bgp vrf {args.vrf} summary"
    return "show ip bgp summary"


def main():
    parser = argparse.ArgumentParser(
        description="BGP peer session monitor — flags non-Established peers."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None,
                        help="SSH password (prompted if omitted and no key given)")
    parser.add_argument("--key", dest="key_file", default=None,
                        help="Path to SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", default=None, help="VRF name for BGP lookup")
    parser.add_argument("--ipv6", action="store_true",
                        help="Query IPv6 unicast BGP table instead of IPv4")
    parser.add_argument("--timeout", type=int, default=15,
                        help="SSH connection timeout in seconds (default: 15)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.key_file and args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    command = build_command(args)
    log.info("Connecting to %s:%d", args.device, args.port)

    try:
        client = ssh_connect(
            args.device, args.username,
            password=args.password,
            key_file=args.key_file,
            port=args.port,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.debug("Running: %s", command)
        output = run_command(client, command, timeout=args.timeout)
        log.debug("Raw output:\n%s", output)
    except Exception as exc:
        log.error("Command execution failed: %s", exc)
        sys.exit(1)
    finally:
        client.close()

    if not output.strip():
        log.error("No output received — BGP may not be configured or the VRF name is wrong.")
        sys.exit(2)

    data = parse_bgp_summary(output)

    if not data["peers"]:
        log.warning("No BGP peers parsed from output. Use -v to see raw output.")
        sys.exit(2)

    all_good = print_report(data, args.device)
    sys.exit(0 if all_good else 1)


if __name__ == "__main__":
    main()