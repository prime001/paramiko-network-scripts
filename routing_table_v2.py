```python
#!/usr/bin/env python3
"""
Device Performance Monitor

Monitors network device performance metrics including CPU utilization, memory usage,
and uptime via SSH using paramiko. Collects key operational metrics for capacity
planning and troubleshooting.

Usage:
    python device_perf_monitor.py -d 192.168.1.1 -u admin -p password
    python device_perf_monitor.py -d 192.168.1.1 -u admin -p password -o metrics.json

Prerequisites:
    - Network device with SSH enabled
    - Paramiko library installed (pip install paramiko)
    - Credentials with appropriate permissions
    - Support for standard Cisco show commands
"""

import argparse
import json
import logging
import re
import sys
from typing import Dict, Optional

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DevicePerformanceMonitor:
    """Collects device performance metrics via SSH."""

    def __init__(self, host: str, username: str, password: str, timeout: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = None
        self.metrics = {}

    def connect(self) -> bool:
        """Establish SSH connection to device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, username=self.username,
                              password=self.password, timeout=self.timeout)
            logger.info(f"Connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {self.host}")
            return False
        except (paramiko.SSHException, Exception) as e:
            logger.error(f"Connection failed: {e}")
            return False

    def _execute_command(self, command: str) -> str:
        """Execute SSH command and return output."""
        try:
            stdin, stdout, stderr = self.client.exec_command(command,
                                                             timeout=self.timeout)
            return stdout.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return ""

    def get_uptime(self) -> Optional[str]:
        """Extract device uptime from show version."""
        try:
            output = self._execute_command("show version")
            match = re.search(r'uptime is (.+?)$', output, re.MULTILINE)
            if match:
                uptime = match.group(1).strip()
                self.metrics['uptime'] = uptime
                return uptime
        except Exception as e:
            logger.warning(f"Uptime retrieval failed: {e}")
        return None

    def get_cpu_usage(self) -> Optional[float]:
        """Extract CPU utilization percentage."""
        try:
            output = self._execute_command("show processes cpu")
            match = re.search(r'CPU utilization for five seconds: (\d+)%', output)
            if match:
                cpu = float(match.group(1))
                self.metrics['cpu_5sec_percent'] = cpu
                return cpu
        except Exception as e:
            logger.warning(f"CPU retrieval failed: {e}")
        return None

    def get_memory_usage(self) -> Optional[Dict]:
        """Extract memory utilization stats."""
        try:
            output = self._execute_command("show memory")
            match = re.search(
                r'Processor Memory\s+.*?(\d+)K total.*?(\d+)K used.*?(\d+)K free',
                output, re.DOTALL
            )
            if match:
                total_kb = int(match.group(1))
                used_kb = int(match.group(2))
                usage_pct = (used_kb / total_kb * 100) if total_kb else 0
                mem_info = {
                    'total_kb': total_kb,
                    'used_kb': used_kb,
                    'usage_percent': round(usage_pct, 2)
                }
                self.metrics['memory'] = mem_info
                return mem_info
        except Exception as e:
            logger.warning(f"Memory retrieval failed: {e}")
        return None

    def get_interface_status(self) -> Optional[Dict]:
        """Extract interface operational status."""
        try:
            output = self._execute_command("show interface brief | include up")
            up_count = len([line for line in output.split('\n') if line.strip()])
            output_all = self._execute_command("show interface brief")
            total_count = len([line for line in output_all.split('\n')
                             if re.match(r'^\w+', line)])
            if total_count > 0:
                interface_info = {
                    'total': total_count,
                    'up': up_count,
                    'down': total_count - up_count
                }
                self.metrics['interfaces'] = interface_info
                return interface_info
        except Exception as e:
            logger.warning(f"Interface status retrieval failed: {e}")
        return None

    def collect_metrics(self) -> bool:
        """Collect all performance metrics."""
        if not self.connect():
            return False

        try:
            logger.info("Collecting device metrics...")
            self.get_uptime()
            self.get_cpu_usage()
            self.get_memory_usage()
            self.get_interface_status()
            logger.info("Metrics collection completed")
            return True
        except Exception as e:
            logger.error(f"Collection error: {e}")
            return False
        finally:
            if self.client:
                self.client.close()

    def display_metrics(self):
        """Print formatted metrics output."""
        print(f"\n{'='*60}")
        print(f"Device Performance Report: {self.host}")
        print(f"{'='*60}")
        for key, value in self.metrics.items():
            if isinstance(value, dict):
                print(f"\n{key.upper()}:")
                for k, v in value.items():
                    print(f"  {k}: {v}")
            else:
                print(f"{key}: {value}")
        print(f"{'='*60}\n")

    def save_metrics_json(self, filepath: str):
        """Export metrics to JSON file."""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.metrics, f, indent=2)
            logger.info(f"Metrics saved to {filepath}")
        except Exception as e:
            logger.error(f"Save failed: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor network device performance metrics'
    )
    parser.add_argument('-d', '--device', required=True,
                       help='Target device IP address')
    parser.add_argument('-u', '--username', required=True,
                       help='SSH username')
    parser.add_argument('-p', '--password', required=True,
                       help='SSH password')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='SSH timeout seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Save metrics to JSON file')

    args = parser.parse_args()

    monitor = DevicePerformanceMonitor(
        host=args.device,
        username=args.username,
        password=args.password,
        timeout=args.timeout
    )

    if monitor.collect_metrics():
        monitor.display_metrics()
        if args.output:
            monitor.save_metrics_json(args.output)
        sys.exit(0)
    else:
        logger.error("Failed to collect metrics")
        sys.exit(1)


if __name__ == "__main__":
    main()
```