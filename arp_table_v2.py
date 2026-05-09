```python
"""
Device Health Monitor - Retrieve system health metrics from network devices.

Purpose:
    Connects to network devices and retrieves key health metrics including uptime,
    CPU usage, memory utilization, and interface statistics. Useful for monitoring
    device health and capacity planning.

Usage:
    python device_health_monitor.py --device 192.168.1.1 --username admin --password pass
    python device_health_monitor.py --device 192.168.1.1 -u admin -p pass --csv health.csv
    python device_health_monitor.py --device sw01.example.com -u admin -p pass --verbose

Prerequisites:
    - paramiko library installed (pip install paramiko)
    - SSH access enabled on target devices
    - User account with sufficient privileges to view system information
    - Network connectivity to target device

Examples:
    Basic health check:
        python device_health_monitor.py --device 10.0.0.1 -u admin -p Password123

    Export to CSV:
        python device_health_monitor.py --device 10.0.0.1 -u admin -p pass --csv report.csv

    Verbose output:
        python device_health_monitor.py --device 10.0.0.1 -u admin -p pass -v
"""

import argparse
import logging
import paramiko
import re
import sys
import csv
from datetime import datetime
from typing import Dict, Optional


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceHealthMonitor:
    """Monitor and retrieve health metrics from network devices."""

    def __init__(self, host: str, username: str, password: str, timeout: int = 10):
        """Initialize SSH connection parameters."""
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = None

    def connect(self) -> bool:
        """Establish SSH connection to device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.host,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Successfully connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {self.host}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def send_command(self, command: str) -> str:
        """Send command and return output."""
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            output = stdout.read().decode('utf-8')
            return output
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return ""

    def parse_uptime(self, uptime_output: str) -> Optional[str]:
        """Extract uptime from device output."""
        match = re.search(r'uptime is (.+?)$', uptime_output, re.MULTILINE | re.IGNORECASE)
        return match.group(1).strip() if match else None

    def parse_cpu(self, cpu_output: str) -> Optional[str]:
        """Extract CPU usage percentage."""
        match = re.search(r'(\d+)%', cpu_output)
        return match.group(1) + '%' if match else None

    def parse_memory(self, mem_output: str) -> Optional[Dict[str, str]]:
        """Extract memory usage information."""
        used_match = re.search(r'(\d+)K\s*used', mem_output)
        total_match = re.search(r'(\d+)K\s*total', mem_output)

        if used_match and total_match:
            used_kb = int(used_match.group(1))
            total_kb = int(total_match.group(1))
            percent = (used_kb / total_kb) * 100
            return {
                'used': f"{used_kb / 1024:.2f}MB",
                'total': f"{total_kb / 1024:.2f}MB",
                'percent': f"{percent:.1f}%"
            }
        return None

    def get_health_metrics(self) -> Dict[str, Optional[str]]:
        """Retrieve all health metrics."""
        metrics = {
            'device': self.host,
            'timestamp': datetime.now().isoformat(),
            'uptime': None,
            'cpu': None,
            'memory': None,
            'status': 'unknown'
        }

        if not self.connect():
            metrics['status'] = 'offline'
            return metrics

        try:
            uptime_output = self.send_command("show version")
            metrics['uptime'] = self.parse_uptime(uptime_output)

            cpu_output = self.send_command("show processes cpu")
            metrics['cpu'] = self.parse_cpu(cpu_output)

            mem_output = self.send_command("show memory")
            mem_info = self.parse_memory(mem_output)
            if mem_info:
                metrics['memory'] = f"{mem_info['used']}/{mem_info['total']} ({mem_info['percent']})"

            metrics['status'] = 'online'
        except Exception as e:
            logger.error(f"Error retrieving metrics: {e}")
            metrics['status'] = 'error'
        finally:
            self.disconnect()

        return metrics

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
            logger.info(f"Disconnected from {self.host}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Retrieve health metrics from network devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  %(prog)s --device 10.0.0.1 -u admin -p pass\n'
               '  %(prog)s --device sw01 -u admin -p pass --csv health.csv'
    )
    parser.add_argument('--device', '-d', required=True, help='Device hostname or IP address')
    parser.add_argument('--username', '-u', required=True, help='SSH username')
    parser.add_argument('--password', '-p', required=True, help='SSH password')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--csv', help='Export results to CSV file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    monitor = DeviceHealthMonitor(args.device, args.username, args.password, args.timeout)
    metrics = monitor.get_health_metrics()

    print("\n" + "="*60)
    print(f"Device Health Report: {metrics['device']}")
    print("="*60)
    print(f"Status:     {metrics['status']}")
    print(f"Timestamp:  {metrics['timestamp']}")
    print(f"Uptime:     {metrics['uptime'] or 'N/A'}")
    print(f"CPU Usage:  {metrics['cpu'] or 'N/A'}")
    print(f"Memory:     {metrics['memory'] or 'N/A'}")
    print("="*60 + "\n")

    if args.csv:
        try:
            with open(args.csv, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=metrics.keys())
                if f.tell() == 0:
                    writer.writeheader()
                writer.writerow(metrics)
            logger.info(f"Results exported to {args.csv}")
        except IOError as e:
            logger.error(f"Failed to write CSV: {e}")
            return 1

    return 0 if metrics['status'] == 'online' else 1


if __name__ == "__main__":
    sys.exit(main())
```