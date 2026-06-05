```python
"""
Network Device Health Monitor

Connects to network devices via SSH and collects system health metrics
including CPU, memory, and uptime information. Supports multiple devices
from a file or single device input.

Usage:
    python device_health_monitor.py -d 192.168.1.1 -u admin -p password
    python device_health_monitor.py -d devices.txt -u admin -p password --format json

Prerequisites:
    - paramiko library installed
    - SSH access to target network devices
    - Valid device credentials (username/password)
    - Devices support 'show version', 'show processes cpu', 'show memory' commands
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

import paramiko


class DeviceHealthMonitor:
    """Monitor and collect health metrics from network devices."""

    def __init__(self, host: str, username: str, password: str, timeout: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = None
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            self.logger.info(f"Connected to {self.host}")
            return True
        except (paramiko.SSHException, TimeoutError) as e:
            self.logger.error(f"Connection failed to {self.host}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error on {self.host}: {e}")
            return False

    def execute_command(self, command: str) -> Optional[str]:
        """Execute SSH command and return output."""
        if not self.client:
            return None

        try:
            _, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            output = stdout.read().decode("utf-8", errors="ignore").strip()
            return output
        except Exception as e:
            self.logger.warning(f"Command failed on {self.host}: {e}")
            return None

    def collect_metrics(self) -> Dict:
        """Collect device health metrics."""
        metrics = {"device": self.host, "status": "unknown"}

        version = self.execute_command("show version")
        if version:
            metrics["status"] = "reachable"
            uptime = self._extract_uptime(version)
            if uptime:
                metrics["uptime"] = uptime

        cpu = self.execute_command("show processes cpu")
        if cpu:
            cpu_usage = self._extract_cpu(cpu)
            if cpu_usage is not None:
                metrics["cpu_percent"] = cpu_usage

        memory = self.execute_command("show memory")
        if memory:
            mem_data = self._extract_memory(memory)
            if mem_data:
                metrics["memory"] = mem_data

        return metrics

    @staticmethod
    def _extract_uptime(output: str) -> Optional[str]:
        """Extract uptime from show version."""
        match = re.search(r"uptime is (.+?)(?:\n|$)", output, re.IGNORECASE)
        return match.group(1).strip() if match else None

    @staticmethod
    def _extract_cpu(output: str) -> Optional[float]:
        """Extract CPU utilization percentage."""
        match = re.search(r"CPU utilization[:\s]+(\d+(?:\.\d+)?)\s*%", output)
        return float(match.group(1)) if match else None

    @staticmethod
    def _extract_memory(output: str) -> Optional[Dict]:
        """Extract memory usage."""
        total_match = re.search(r"Total:?\s+(\d+)", output)
        used_match = re.search(r"Used:?\s+(\d+)", output)

        if total_match and used_match:
            total = int(total_match.group(1))
            used = int(used_match.group(1))
            return {
                "total_kb": total,
                "used_kb": used,
                "percent_used": round((used / total) * 100, 2),
            }
        return None

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self.client:
            self.client.close()
            self.logger.info(f"Disconnected from {self.host}")


def load_devices(source: str) -> List[str]:
    """Load devices from file or return single device."""
    if Path(source).is_file():
        try:
            with open(source) as f:
                devices = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return devices
        except IOError as e:
            logging.error(f"Failed to read device file: {e}")
            return []
    return [source]


def format_text_output(results: List[Dict]) -> None:
    """Print results in text format."""
    print(f"\n{'Device':<20} {'Status':<12} {'CPU %':<10} {'Memory %':<12} {'Uptime':<30}")
    print("-" * 85)

    for result in results:
        device = result.get("device", "unknown")
        status = result.get("status", "unknown")
        cpu = result.get("cpu_percent", "-")
        cpu_str = f"{cpu:.1f}%" if isinstance(cpu, float) else cpu
        mem = result.get("memory", {})
        mem_str = f"{mem.get('percent_used', '-')}%" if mem else "-"
        uptime = result.get("uptime", "-")

        print(f"{device:<20} {status:<12} {cpu_str:<10} {mem_str:<12} {uptime:<30}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Collect health metrics from network devices"
    )
    parser.add_argument("-d", "--device", required=True,
                        help="Device IP/hostname or file with device list")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="SSH timeout in seconds")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text",
                        help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    devices = load_devices(args.device)
    if not devices:
        logging.error("No devices specified")
        sys.exit(1)

    results = []
    for device in devices:
        monitor = DeviceHealthMonitor(device, args.username, args.password, args.timeout)
        if monitor.connect():
            metrics = monitor.collect_metrics()
            results.append(metrics)
            monitor.disconnect()
        else:
            results.append({"device": device, "status": "unreachable"})

    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        format_text_output(results)


if __name__ == "__main__":
    main()
```