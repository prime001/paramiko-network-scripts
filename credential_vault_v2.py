```python
"""
Device System Uptime and Performance Monitor

Connects to network devices via SSH and collects system uptime and performance
metrics (CPU, memory utilization). Generates reports in text, JSON, or CSV format.

Usage:
    python device_monitor.py --device 192.168.1.1 --username admin --password pass
    python device_monitor.py --hosts devices.txt --username admin --password pass --output json
    python device_monitor.py --hosts devices.txt --username admin --password pass --output csv

Prerequisites:
    - paramiko library installed (pip install paramiko)
    - Network devices must have SSH enabled
    - User credentials must have access to show commands
    - Supported: Cisco IOS, IOS XE, Nexus platforms

Author: Network Automation Team
"""

import paramiko
import logging
import argparse
import json
import csv
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceMonitor:
    """SSH-based device health monitor for collecting uptime and performance metrics."""

    def __init__(self, hostname, username, password, timeout=10):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.metrics = {}

    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.client.connect(
                self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Connected to {self.hostname}")
            return True
        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed for {self.hostname}: {e}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH protocol error on {self.hostname}: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection error on {self.hostname}: {e}")
            return False

    def execute_command(self, command):
        """Execute show command and return output."""
        try:
            stdin, stdout, stderr = self.client.exec_command(
                command, timeout=self.timeout
            )
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            if error and 'invalid' not in error.lower():
                logger.warning(f"Error output from {self.hostname}: {error[:100]}")
            return output
        except Exception as e:
            logger.error(f"Command execution failed on {self.hostname}: {e}")
            return ""

    def get_uptime(self):
        """Extract device uptime from show version output."""
        output = self.execute_command("show version")
        for line in output.split('\n'):
            if 'uptime' in line.lower():
                self.metrics['uptime'] = line.strip()
                return True
        self.metrics['uptime'] = "Unable to retrieve"
        return False

    def get_cpu_utilization(self):
        """Collect CPU utilization metrics."""
        output = self.execute_command("show processes cpu | include CPU utilization")
        self.metrics['cpu_utilization'] = (
            output.strip() if output.strip() else "Not available"
        )

    def get_memory_utilization(self):
        """Collect memory utilization metrics."""
        output = self.execute_command("show memory | include Processor")
        self.metrics['memory_utilization'] = (
            output.strip() if output.strip() else "Not available"
        )

    def collect_metrics(self):
        """Connect to device and collect all metrics."""
        if not self.connect():
            self.metrics['status'] = 'FAILED'
            self.metrics['hostname'] = self.hostname
            self.metrics['timestamp'] = datetime.now().isoformat()
            return False

        try:
            self.get_uptime()
            self.get_cpu_utilization()
            self.get_memory_utilization()
            self.metrics['hostname'] = self.hostname
            self.metrics['timestamp'] = datetime.now().isoformat()
            self.metrics['status'] = 'OK'
            logger.info(f"Metrics collected successfully from {self.hostname}")
            return True
        except Exception as e:
            logger.error(f"Metric collection failed on {self.hostname}: {e}")
            self.metrics['status'] = 'ERROR'
            return False
        finally:
            self.disconnect()

    def disconnect(self):
        """Close SSH connection."""
        try:
            self.client.close()
            logger.debug(f"Disconnected from {self.hostname}")
        except Exception as e:
            logger.warning(f"Error during disconnect from {self.hostname}: {e}")

    def get_metrics(self):
        """Return collected metrics dictionary."""
        return self.metrics


def main():
    parser = argparse.ArgumentParser(
        description='Collect uptime and performance metrics from network devices'
    )
    parser.add_argument('--device', help='Single device IP or hostname')
    parser.add_argument('--hosts', help='File containing device list (one per line)')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--timeout', type=int, default=10, help='SSH timeout seconds')
    parser.add_argument(
        '--output',
        choices=['text', 'json', 'csv'],
        default='text',
        help='Output format'
    )

    args = parser.parse_args()

    devices = []
    if args.device:
        devices = [args.device]
    elif args.hosts:
        try:
            with open(args.hosts, 'r') as f:
                devices = [line.strip() for line in f if line.strip()]
        except IOError as e:
            logger.error(f"Cannot read hosts file: {e}")
            return
    else:
        logger.error("Either --device or --hosts must be specified")
        parser.print_help()
        return

    results = []
    for device in devices:
        monitor = DeviceMonitor(
            device, args.username, args.password, args.timeout
        )
        if monitor.collect_metrics():
            results.append(monitor.get_metrics())

    if not results:
        logger.warning("No devices were successfully monitored")
        return

    if args.output == 'json':
        print(json.dumps(results, indent=2))
    elif args.output == 'csv':
        try:
            with open('device_metrics.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
            logger.info("Results written to device_metrics.csv")
        except Exception as e:
            logger.error(f"Failed to write CSV: {e}")
    else:
        for result in results:
            print(f"\nDevice: {result.get('hostname')}")
            print(f"Status: {result.get('status')}")
            print(f"Timestamp: {result.get('timestamp')}")
            print(f"Uptime: {result.get('uptime', 'N/A')}")
            print(f"CPU: {result.get('cpu_utilization', 'N/A')}")
            print(f"Memory: {result.get('memory_utilization', 'N/A')}")


if __name__ == "__main__":
    main()
```