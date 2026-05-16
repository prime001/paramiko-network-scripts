```python
"""
Interface Error Rate Monitor - Sample and analyze interface error counters over time.

Purpose:
    Connect to a Cisco IOS/IOS-XE device via SSH, collect interface error counters
    at two points in time separated by a configurable interval, and report per-second
    error rates. Flags interfaces exceeding a configurable threshold for input errors,
    CRC errors, output drops, runts, and giants.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \
        --interval 30 --threshold 0.5 --interface GigabitEthernet

Prerequisites:
    pip install paramiko
    SSH access to a Cisco IOS/IOS-XE device with 'show interfaces' privilege
"""

import argparse
import getpass
import logging
import re
import time

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

COUNTER_PATTERNS = {
    "input_errors": re.compile(r"(\d+) input errors"),
    "crc": re.compile(r"(\d+) CRC"),
    "output_drops": re.compile(r"(\d+) output drops"),
    "input_drops": re.compile(r"(\d+) input drops"),
    "runts": re.compile(r"(\d+) runts"),
    "giants": re.compile(r"(\d+) giants"),
}

IFACE_HEADER = re.compile(r"^(\S+) is (up|down|administratively down)", re.MULTILINE)


def ssh_connect(host, port, username, password=None, key_file=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {"hostname": host, "port": port, "username": username, "timeout": 10}
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def run_command(client, command, timeout=20):
    _, stdout, _ = client.exec_command(command, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


def parse_counters(output, iface_filter=None):
    """Split 'show interfaces' output into blocks and extract error counters."""
    blocks = re.split(r"(?=^\S)", output, flags=re.MULTILINE)
    result = {}
    for block in blocks:
        m = IFACE_HEADER.match(block)
        if not m:
            continue
        iface = m.group(1)
        if iface_filter and iface_filter.lower() not in iface.lower():
            continue
        counters = {}
        for key, pattern in COUNTER_PATTERNS.items():
            hit = pattern.search(block)
            counters[key] = int(hit.group(1)) if hit else 0
        result[iface] = counters
    return result


def compute_rates(before, after, elapsed):
    """Return per-second delta for each counter, clamped to zero for counter resets."""
    rates = {}
    for iface in before:
        if iface not in after:
            continue
        rates[iface] = {
            key: max(0, after[iface].get(key, 0) - before[iface].get(key, 0)) / elapsed
            for key in COUNTER_PATTERNS
        }
    return rates


def print_report(rates, threshold):
    flagged, clean = [], []
    for iface, counters in sorted(rates.items()):
        if counters["input_errors"] + counters["output_drops"] >= threshold:
            flagged.append((iface, counters))
        else:
            clean.append(iface)

    if flagged:
        print(f"\n{'='*62}")
        print(f"  INTERFACES WITH ERROR RATE >= {threshold:.2f}/s")
        print(f"{'='*62}")
        for iface, c in flagged:
            active = {k: v for k, v in c.items() if v > 0}
            stats = "  ".join(f"{k}: {v:.2f}/s" for k, v in active.items())
            print(f"  {iface:<35} {stats or 'no active counters'}")

    print(f"\nClean interfaces ({len(clean)}): {', '.join(clean) or 'none'}")
    return len(flagged)


def main():
    parser = argparse.ArgumentParser(
        description="Sample interface error counters on a network device and report rates."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--key", help="Path to SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--interval", type=int, default=10,
        help="Seconds between counter samples (default: 10)",
    )
    parser.add_argument(
        "--threshold", type=float, default=1.0,
        help="Errors/s rate to flag an interface (default: 1.0)",
    )
    parser.add_argument(
        "--interface",
        help="Substring filter for interface names (e.g. 'GigabitEthernet')",
    )
    args = parser.parse_args()

    if not args.key and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    logger.info("Connecting to %s:%d", args.device, args.port)
    try:
        client = ssh_connect(
            args.device, args.port, args.username,
            password=args.password, key_file=args.key,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        raise SystemExit(1)
    except Exception as exc:
        logger.error("Connection failed: %s", exc)
        raise SystemExit(1)

    try:
        logger.info("Collecting first sample...")
        before = parse_counters(run_command(client, "show interfaces"), args.interface)
        t1 = time.monotonic()

        if not before:
            logger.error("No matching interfaces found. Check device or --interface filter.")
            raise SystemExit(1)

        logger.info("Waiting %d seconds before second sample...", args.interval)
        time.sleep(args.interval)

        logger.info("Collecting second sample...")
        after = parse_counters(run_command(client, "show interfaces"), args.interface)
        elapsed = time.monotonic() - t1
    finally:
        client.close()

    rates = compute_rates(before, after, elapsed)
    logger.info("Sampled %d interfaces over %.1f seconds", len(rates), elapsed)
    flagged = print_report(rates, args.threshold)
    raise SystemExit(0 if flagged == 0 else 2)


if __name__ == "__main__":
    main()
```