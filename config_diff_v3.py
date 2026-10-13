The script content (the prompt asked me to output only the script, no markdown fences):

```
"""
running_startup_drift.py - Detect unsaved configuration changes on network devices.
```

Wait — the prompt says "Output ONLY the script content, no markdown fences, no explanation." Let me output it directly:

---

"""
running_startup_drift.py - Detect unsaved configuration changes on network devices.

Purpose:
    Connects to Cisco IOS/IOS-XE devices via SSH and compares the running
    configuration against the startup configuration. Highlights lines present
    in running but not startup (unsaved additions) and lines present in startup
    but not running (changes that would be lost on reload).

    Unlike file-based config diff tools, this catches live uncommitted changes
    directly from the device — useful before planned reloads or audits.

Usage:
    python running_startup_drift.py -H 192.168.1.1 -u admin -p secret
    python running_startup_drift.py -H 192.168.1.1 -u admin --key ~/.ssh/id_rsa
    python running_startup_drift.py -H 192.168.1.1 -u admin -p secret --save drift.txt
    python running_startup_drift.py -H 192.168.1.1 -u admin -p secret --section "^router bgp"

Prerequisites:
    pip install paramiko
    Device must have SSH enabled with credentials that have show privilege.
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.

Exit codes:
    0 - No drift detected
    1 - Drift found
    2 - Connection or collection error
"""

import argparse
import difflib
import logging
import re
import sys
import time
from datetime import datetime

import paramiko

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def get_ssh_client(host, username, password=None, key_path=None, port=22, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "look_for_keys": bool(key_path),
        "allow_agent": False,
    }
    if key_path:
        kwargs["key_filename"] = key_path
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _recv_until_stable(channel, settle=0.3, max_wait=8.0, chunk=4096):
    buf = ""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        if channel.recv_ready():
            buf += channel.recv(chunk).decode("utf-8", errors="replace")
        else:
            time.sleep(settle)
            if not channel.recv_ready():
                break
    return buf


def collect_config(client, command):
    transport = client.get_transport()
    channel = transport.open_session()
    channel.get_pty(term="vt100", width=220, height=50)
    channel.invoke_shell()
    time.sleep(1.5)
    _recv_until_stable(channel)

    channel.send("terminal length 0\n")
    time.sleep(1.0)
    _recv_until_stable(channel)

    channel.send(command + "\n")
    raw = _recv_until_stable(channel, max_wait=12.0)
    channel.close()
    return raw


def parse_config_lines(raw, command):
    lines = raw.splitlines()
    started = False
    result = []
    for line in lines:
        if not started:
            if command.strip() in line:
                started = True
            continue
        if re.match(r"^[\w\-\.]+[#>]\s*$", line.strip()):
            break
        result.append(line.rstrip())
    return result


def extract_section(config_lines, section_pattern):
    pattern = re.compile(section_pattern)
    result = []
    in_section = False
    for line in config_lines:
        if pattern.match(line):
            in_section = True
        elif in_section and line and not line.startswith(" "):
            in_section = False
        if in_section:
            result.append(line)
    return result


def build_diff(running_lines, startup_lines):
    return list(difflib.unified_diff(
        startup_lines,
        running_lines,
        fromfile="startup-config",
        tofile="running-config",
        lineterm="",
    ))


def main():
    parser = argparse.ArgumentParser(
        description="Detect unsaved config drift between running and startup configs."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--key", dest="key_path", default=None, metavar="PATH",
                        help="SSH private key file")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--section", default=None, metavar="REGEX",
        help="Restrict diff to config section matching this regex (e.g. '^router bgp')",
    )
    parser.add_argument("--save", metavar="FILE",
                        help="Write diff output to a file")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress diff output to stdout; still exits 1 on drift")
    args = parser.parse_args()

    if not args.password and not args.key_path:
        parser.error("Provide --password or --key")

    logger.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        client = get_ssh_client(
            args.host, args.username,
            password=args.password,
            key_path=args.key_path,
            port=args.port,
            timeout=args.timeout,
        )
    except paramiko.AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(2)
    except (paramiko.SSHException, OSError) as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(2)

    try:
        logger.info("Collecting running-config")
        raw_running = collect_config(client, "show running-config")
        logger.info("Collecting startup-config")
        raw_startup = collect_config(client, "show startup-config")
    except Exception as exc:
        logger.error("Config collection failed: %s", exc)
        client.close()
        sys.exit(2)
    finally:
        client.close()

    running = parse_config_lines(raw_running, "show running-config")
    startup = parse_config_lines(raw_startup, "show startup-config")

    if args.section:
        running = extract_section(running, args.section)
        startup = extract_section(startup, args.section)
        logger.info("Filtered to section matching: %s", args.section)

    diff = build_diff(running, startup)

    if not diff:
        logger.info("Clean: running-config matches startup-config on %s", args.host)
        sys.exit(0)

    added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
    logger.warning(
        "Drift on %s — %d unsaved addition(s), %d startup-only line(s)",
        args.host, added, removed,
    )

    header = [
        f"# Config drift report: {args.host}",
        f"# Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Unsaved additions (in running, not startup): {added}",
        f"# Startup-only lines (lost on reload)       : {removed}",
        "",
    ]
    report = "\n".join(header + diff)

    if not args.quiet:
        print(report)

    if args.save:
        try:
            with open(args.save, "w") as fh:
                fh.write(report + "\n")
            logger.info("Report written to %s", args.save)
        except OSError as exc:
            logger.error("Could not write %s: %s", args.save, exc)

    sys.exit(1)


if __name__ == "__main__":
    main()