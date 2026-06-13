```python
#!/usr/bin/env python3
"""
System Resource Monitor

Collect system resource metrics from network devices including CPU utilization,
memory usage, disk space, and uptime. Supports Cisco IOS, IOS-XE, and NX-OS.

Usage:
    python system_resource_monitor.py -d 192.168.1.1 -u admin -p password
    python system_resource_monitor.py -f devices.txt -u admin -k /path/to/key --output report.csv

Prerequisites:
    - paramiko library installed
    - SSH enabled on target devices
    - User credentials with read access
"""

import argparse
import csv
import json
import logging
import sys
from datetime import datetime
from typing import Dict, Optional

import paramiko
from paramiko.ssh_exception import SSHException, AuthException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SystemResourceMonitor:
    """Monitor system resources on network devices via SSH."""

    def __init__(self, host: str, username: str, password: Optional[str] = None,
                 key_file: Optional[str] = None, timeout: int = 30):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.client = None

    def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if self.key_file:
                self.client.connect(
                    self.host,
                    username=self.username,
                    key_filename=self.key_file,
                    timeout=self.timeout,
                    allow_agent=False
                )
            else:
                self.client.connect(
                    self.host,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    allow_agent=False
                )
            logger.info(f"Connected to {self.host}")
            return True
        except (AuthException, SSHException) as e:
            logger.error(f"Connection failed for {self.host}: {e}")
            return False

    def execute_command(self, command: str) -> str:
        """Execute command and return output."""
        if not self.client:
            return ""
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            return stdout.read().decode('utf-8').strip()
        except Exception as e:
            logger.error(f"Command failed on {self.host}: {e}")
            return ""

    def get_cpu_utilization(self) -> str:
        """Extract CPU utilization from show processes cpu."""
        output = self.execute_command("show processes cpu | include CPU")
        for line in output.split('\n'):
            if "CPU utilization" in line:
                parts = line.split(',')
                for part in parts:
                    if "1 minute" in part:
                        return part.split(':')[1].strip() if ':' in part else "N/A"
        return "N/A"

    def get_memory_usage(self) -> str:
        """Extract memory usage."""
        output = self.execute_command("show memory statistics | include Memory")
        for line in output.split('\n'):
            if "Memory usage" in line or "Total memory" in line:
                parts = line.split()
                if len(parts) >= 3:
                    return f"{parts[2]} {parts[3] if len(parts) > 3 else '%'}"
        return "N/A"

    def get_uptime(self) -> str:
        """Extract device uptime."""
        output = self.execute_command("show version | include uptime")
        if output:
            return output.split("uptime is")[-1].strip() if "uptime is" in output else output
        return "N/A"

    def get_temperature(self) -> str:
        """Extract system temperature."""
        output = self.execute_command("show environment | include Temperature")
        if output:
            return output.split('\n')[0].strip()
        return "N/A"

    def collect_resources(self) -> Dict:
        """Collect all system metrics."""
        return {
            'timestamp': datetime.now().isoformat(),
            'device': self.host,
            'cpu_utilization': self.get_cpu_utilization(),
            'memory_usage': self.get_memory_usage(),
            'uptime': self.get_uptime(),
            'temperature': self.get_temperature(),
        }

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Monitor system resources on network devices"
    )
    parser.add_argument('-d', '--device', help='Target device IP/hostname')
    parser.add_argument('-f', '--file', help='File with device list (one per line)')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password')
    parser.add_argument('-k', '--key', help='SSH private key file')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='SSH timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('--format', choices=['csv', 'json'], default='csv',
                        help='Output format')

    args = parser.parse_args()

    if not args.device and not args.file:
        parser.error("Either --device or --file must be specified")

    if not args.password and not args.key:
        parser.error("Either --password or --key must be specified")

    devices = []
    if args.device:
        devices = [args.device]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                devices = [line.strip() for line in f if line.strip()]
        except IOError as e:
            logger.error(f"Failed to read device file: {e}")
            sys.exit(1)

    results = []
    for device in devices:
        monitor = SystemResourceMonitor(
            device, args.username, args.password, args.key, args.timeout
        )
        if monitor.connect():
            results.append(monitor.collect_resources())
            monitor.disconnect()

    if not results:
        logger.error("No successful connections")
        sys.exit(1)

    if args.format == 'json':
        output = json.dumps(results, indent=2)
    else:
        output_lines = []
        fieldnames = list(results[0].keys()) if results else []
        writer = csv.DictWriter(output_lines, fieldnames=fieldnames)

        import io
        output_buffer = io.StringIO()
        writer = csv.DictWriter(output_buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
        output = output_buffer.getvalue()

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(output)
            logger.info(f"Results written to {args.output}")
        except IOError as e:
            logger.error(f"Failed to write output file: {e}")
            sys.exit(1)
    else:
        print(output)


if __name__ == "__main__":
    main()
```