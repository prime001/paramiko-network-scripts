```python
"""
arp_correlation.py — Cross-device ARP anomaly detector

Collects ARP tables from multiple network devices via SSH and performs
cross-device correlation to surface anomalies: duplicate IPs mapped to
different MACs (potential ARP spoofing) and MACs appearing on multiple IPs
(potential scanning or misconfiguration).

Usage:
    python arp_correlation.py --hosts 192.168.1.1 192.168.1.2 \
        --username admin --password secret
    python arp_correlation.py --hosts-file devices.txt -u admin \
        --key ~/.ssh/id_rsa --output results.json

Prerequisites:
    pip install paramiko
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ARP_PATTERN = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|"
    r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
)


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    return ":".join(digits[i:i+2] for i in range(0, 12, 2))


def fetch_arp_table(host: str, username: str, password: str | None,
                    key_path: str | None, port: int, timeout: int) -> list[dict]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = {
            "hostname": host, "port": port, "username": username,
            "timeout": timeout, "look_for_keys": False, "allow_agent": False,
        }
        if key_path:
            connect_kwargs["key_filename"] = key_path
        elif password:
            connect_kwargs["password"] = password
        else:
            raise ValueError("Provide --password or --key")

        client.connect(**connect_kwargs)
        _, stdout, stderr = client.exec_command("show arp", timeout=timeout)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.debug("%s stderr: %s", host, err)

        entries = []
        for match in ARP_PATTERN.finditer(output):
            entries.append({
                "ip": match.group(1),
                "mac": normalize_mac(match.group(2)),
                "source": host,
            })
        log.info("%s: %d ARP entries collected", host, len(entries))
        return entries
    except Exception as exc:
        log.error("%s: connection failed — %s", host, exc)
        return []
    finally:
        client.close()


def correlate(all_entries: list[dict]) -> dict:
    ip_to_macs: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    mac_to_ips: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    for e in all_entries:
        ip_to_macs[e["ip"]][e["mac"]].append(e["source"])
        mac_to_ips[e["mac"]][e["ip"]].append(e["source"])

    dup_ip = {
        ip: dict(macs)
        for ip, macs in ip_to_macs.items()
        if len(macs) > 1
    }
    dup_mac = {
        mac: dict(ips)
        for mac, ips in mac_to_ips.items()
        if len(ips) > 1
    }

    return {
        "total_entries": len(all_entries),
        "unique_ips": len(ip_to_macs),
        "unique_macs": len(mac_to_ips),
        "anomalies": {
            "duplicate_ip_mappings": dup_ip,
            "mac_on_multiple_ips": dup_mac,
        },
        "summary": {
            "duplicate_ip_count": len(dup_ip),
            "roaming_mac_count": len(dup_mac),
        },
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Cross-device ARP correlation and anomaly detection")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--hosts", nargs="+", metavar="HOST")
    src.add_argument("--hosts-file", metavar="FILE",
                     help="File with one hostname/IP per line")
    p.add_argument("-u", "--username", required=True)
    cred = p.add_mutually_exclusive_group()
    cred.add_argument("-p", "--password")
    cred.add_argument("-k", "--key", metavar="PATH", help="SSH private key file")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--output", metavar="FILE", help="Write JSON results to file")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.hosts_file:
        with open(args.hosts_file) as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        hosts = args.hosts

    all_entries: list[dict] = []
    for host in hosts:
        entries = fetch_arp_table(
            host, args.username, args.password, args.key,
            args.port, args.timeout,
        )
        all_entries.extend(entries)

    if not all_entries:
        log.error("No ARP entries collected from any device")
        sys.exit(1)

    results = correlate(all_entries)
    results["devices_queried"] = hosts
    results["entries"] = all_entries

    output_json = json.dumps(results, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        log.info("Results written to %s", args.output)
    else:
        print(output_json)

    s = results["summary"]
    log.info(
        "Done — %d entries, %d duplicate-IP anomalies, %d roaming-MAC anomalies",
        results["total_entries"], s["duplicate_ip_count"], s["roaming_mac_count"],
    )


if __name__ == "__main__":
    main()
```