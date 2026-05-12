The write was blocked by permissions. Here is the complete script content — you can save it as `arp_table_v3.py`:

```python
"""
arp_table_v3.py - ARP Table Collector with MAC Vendor Enrichment

Purpose:
    Retrieves the ARP table from a network device via SSH and enriches each
    entry with manufacturer information based on the MAC OUI prefix. Useful
    for asset discovery, rogue device detection, and network auditing when
    you need to know *what* is mapped at each address, not just *that* it is.

Usage:
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret --vrf MGMT
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret --output json
    python arp_table_v3.py -d 192.168.1.1 -u admin -p secret --no-vendor

Prerequisites:
    pip install paramiko requests
"""

import argparse
import json
import logging
import re
import sys
import time

import paramiko
import requests

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

OUI_API_URL = "https://api.macvendors.com/{}"

# Fallback table for common OUIs when the API is unavailable
KNOWN_OUIS: dict[str, str] = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:11": "Google",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "00:1b:63": "Apple",
    "3c:22:fb": "Apple",
    "00:1d:09": "Dell",
    "14:18:77": "Dell",
    "00:25:90": "Super Micro",
    "fc:15:b4": "Cisco",
    "00:1e:49": "Cisco",
    "00:1a:a1": "Cisco",
    "00:0e:84": "Fortinet",
    "00:09:0f": "Fortinet",
    "00:1c:7f": "Palo Alto Networks",
}


def lookup_vendor(mac: str, rate_limit: float) -> str:
    oui = mac[:8].lower()
    if oui in KNOWN_OUIS:
        return KNOWN_OUIS[oui]
    try:
        resp = requests.get(OUI_API_URL.format(mac), timeout=4)
        time.sleep(rate_limit)
        if resp.status_code == 200:
            return resp.text.strip()
        if resp.status_code == 404:
            return "Unknown"
        logger.debug("OUI API returned %d for %s", resp.status_code, mac)
        return "Lookup failed"
    except requests.RequestException as exc:
        logger.debug("OUI lookup error for %s: %s", mac, exc)
        return "Lookup failed"


def ssh_connect(host: str, username: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client: paramiko.SSHClient, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=30)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        logger.warning("Device stderr: %s", err)
    return output


def normalize_mac(raw: str) -> str:
    """Convert IOS dot-notation (0050.5600.0001) or dash-separated to colon notation."""
    if "." in raw:
        hex_str = raw.replace(".", "")
        return ":".join(hex_str[i:i + 2] for i in range(0, 12, 2)).lower()
    return raw.lower().replace("-", ":")


def parse_arp_table(output: str) -> list[dict]:
    entries = []
    # Matches Cisco IOS/IOS-XE: IP, age, MAC (dot or colon/dash), type, interface
    pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})"
        r"\s+\S+"
        r"\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
        r"|[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){4})"
        r"\s+\S+"
        r"\s+(\S+)"
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            ip, mac_raw, interface = m.group(1), m.group(2), m.group(3)
            entries.append({
                "ip": ip,
                "mac": normalize_mac(mac_raw),
                "interface": interface,
            })
    return entries


def enrich_with_vendors(entries: list[dict], rate_limit: float) -> list[dict]:
    oui_cache: dict[str, str] = {}
    for entry in entries:
        oui = entry["mac"][:8]
        if oui not in oui_cache:
            oui_cache[oui] = lookup_vendor(entry["mac"], rate_limit)
        entry["vendor"] = oui_cache[oui]
    return entries


def print_table(entries: list[dict]) -> None:
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Interface':<20} Vendor")
    print("-" * 82)
    for e in entries:
        vendor = e.get("vendor", "")
        print(f"{e['ip']:<18} {e['mac']:<20} {e['interface']:<20} {vendor}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect ARP table with MAC vendor enrichment via SSH"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default="", help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--vrf", help="VRF name (e.g. MGMT)")
    parser.add_argument(
        "--output", choices=["table", "json"], default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "--no-vendor", action="store_true",
        help="Skip MAC vendor lookup (faster, no external requests)"
    )
    parser.add_argument(
        "--rate-limit", type=float, default=0.5, metavar="SECONDS",
        help="Delay between OUI API calls in seconds (default: 0.5)"
    )
    args = parser.parse_args()

    command = f"show arp vrf {args.vrf}" if args.vrf else "show arp"

    try:
        logger.info("Connecting to %s:%d", args.device, args.port)
        client = ssh_connect(args.device, args.username, args.password, args.port)
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for user '%s' on %s", args.username, args.device)
        sys.exit(1)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        logger.info("Running: %s", command)
        raw_output = run_command(client, command)
    finally:
        client.close()

    entries = parse_arp_table(raw_output)
    if not entries:
        logger.warning("No ARP entries parsed — check device output format")
        sys.exit(0)

    logger.info("Parsed %d ARP entries", len(entries))

    if not args.no_vendor:
        logger.info("Enriching with vendor data (rate limit: %.1fs between calls)", args.rate_limit)
        entries = enrich_with_vendors(entries, args.rate_limit)

    if args.output == "json":
        print(json.dumps(entries, indent=2))
    else:
        print_table(entries)


if __name__ == "__main__":
    main()
```

The key differentiator from `arp_table.py` / `arp_table_v2.py` is MAC OUI vendor enrichment: it deduplicates OUI lookups (one API call per unique OUI prefix, not per entry), includes a local fallback table for common vendors (Cisco, VMware, Dell, etc.), and rate-limits external calls to avoid hitting the macvendors.com API limit. `--no-vendor` drops to a plain ARP dump, `--output json` enables pipeline-friendly output.