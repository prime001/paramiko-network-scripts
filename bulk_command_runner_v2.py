Now I'll write the script — a parallel bulk command runner with CSV inventory, threading, and structured JSON report output, which is distinct from a basic sequential runner.

```python
"""
Parallel Bulk Command Runner for Network Devices
================================================
Executes one or more show commands across a fleet of devices concurrently
using a thread pool, then writes a timestamped JSON report.

Purpose:
    Run read-only (show/display) commands against many devices simultaneously
    and collect all output in a single structured report.  Useful for ad-hoc
    audits, pre/post-change verification, and compliance checks.

Usage:
    python bulk_command_runner.py -i inventory.csv -c "show version" "show ip int brief"
    python bulk_command_runner.py -i inventory.csv -c "show version" --threads 20 --timeout 30
    python bulk_command_runner.py -i inventory.csv -c "show version" --output results.json

Prerequisites:
    pip install paramiko
    Inventory CSV must have headers: host, username, password[, port]
    Devices must allow SSH key algorithms supported by the installed OpenSSH/paramiko.

Inventory CSV example:
    host,username,password,port
    192.168.1.1,admin,secret,22
    192.168.1.2,admin,secret,22
"""

import argparse
import csv
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

DEFAULT_PORT = 22
DEFAULT_TIMEOUT = 20
DEFAULT_THREADS = 10
DEFAULT_BANNER_TIMEOUT = 15
RECV_BUFFER = 65535


def load_inventory(csv_path: str) -> list[dict]:
    """Parse device inventory from a CSV file."""
    devices = []
    path = Path(csv_path)
    if not path.is_file():
        logger.error("Inventory file not found: %s", csv_path)
        sys.exit(1)

    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        required = {"host", "username", "password"}
        if not required.issubset(set(reader.fieldnames or [])):
            logger.error("CSV missing required columns: %s", required)
            sys.exit(1)
        for row in reader:
            row["port"] = int(row.get("port") or DEFAULT_PORT)
            devices.append(row)

    if not devices:
        logger.error("Inventory file is empty: %s", csv_path)
        sys.exit(1)

    logger.info("Loaded %d device(s) from %s", len(devices), csv_path)
    return devices


def run_commands_on_device(device: dict, commands: list[str], timeout: int) -> dict:
    """SSH into a device, run all commands, and return structured results."""
    host = device["host"]
    result = {
        "host": host,
        "port": device["port"],
        "status": "error",
        "commands": {},
        "error": None,
        "elapsed_seconds": None,
    }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    t0 = time.monotonic()

    try:
        client.connect(
            hostname=host,
            port=device["port"],
            username=device["username"],
            password=device["password"],
            timeout=timeout,
            banner_timeout=DEFAULT_BANNER_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )

        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read(RECV_BUFFER).decode("utf-8", errors="replace").strip()
            err = stderr.read(RECV_BUFFER).decode("utf-8", errors="replace").strip()
            result["commands"][cmd] = {"output": out, "stderr": err or None}
            logger.debug("[%s] Ran: %s (%d bytes)", host, cmd, len(out))

        result["status"] = "success"

    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed"
        logger.warning("[%s] Authentication failed", host)
    except paramiko.SSHException as exc:
        result["error"] = f"SSH error: {exc}"
        logger.warning("[%s] SSH error: %s", host, exc)
    except OSError as exc:
        result["error"] = f"Connection error: {exc}"
        logger.warning("[%s] Connection error: %s", host, exc)
    finally:
        client.close()
        result["elapsed_seconds"] = round(time.monotonic() - t0, 2)

    return result


def run_bulk(
    devices: list[dict],
    commands: list[str],
    timeout: int,
    max_workers: int,
) -> list[dict]:
    """Run commands across all devices in parallel."""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(run_commands_on_device, dev, commands, timeout): dev["host"]
            for dev in devices
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                logger.error("[%s] Unexpected error: %s", host, exc)
                result = {"host": host, "status": "error", "error": str(exc)}
            results.append(result)
            status = result.get("status", "error")
            logger.info("[%s] %s", host, status.upper())

    results.sort(key=lambda r: r["host"])
    return results


def write_report(results: list[dict], output_path: str, commands: list[str]) -> None:
    """Write results to a JSON report file."""
    success = sum(1 for r in results if r.get("status") == "success")
    report = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "commands": commands,
        "summary": {
            "total": len(results),
            "success": success,
            "error": len(results) - success,
        },
        "devices": results,
    }
    Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Report written to %s (%d/%d succeeded)", output_path, success, len(results))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run show commands across multiple devices in parallel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-i", "--inventory", required=True, metavar="CSV",
        help="Path to inventory CSV (host, username, password[, port])",
    )
    parser.add_argument(
        "-c", "--commands", required=True, nargs="+", metavar="CMD",
        help="One or more commands to execute on every device",
    )
    parser.add_argument(
        "-o", "--output", default="", metavar="FILE",
        help="Output JSON report path (default: bulk_results_<timestamp>.json)",
    )
    parser.add_argument(
        "--threads", type=int, default=DEFAULT_THREADS, metavar="N",
        help=f"Max concurrent SSH sessions (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SEC",
        help=f"Per-device SSH/command timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug-level logging",
    )
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    output_path = args.output or f"bulk_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    devices = load_inventory(args.inventory)
    logger.info("Running %d command(s) across %d device(s) with %d threads",
                len(args.commands), len(devices), args.threads)

    results = run_bulk(devices, args.commands, args.timeout, args.threads)
    write_report(results, output_path, args.commands)

    failed = sum(1 for r in results if r.get("status") != "success")
    sys.exit(1 if failed else 0)
```