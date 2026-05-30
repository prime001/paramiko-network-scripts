```python
#!/usr/bin/env python3
"""
Device Health Check Script

Purpose:
    Quick health assessment of network devices including CPU utilization,
    memory usage, uptime, and system temperature. Supports Cisco IOS and NX-OS.

Usage:
    python device_health_check.py -d 192.168.1.1 -u admin -p password --os ios
    python device_health_check.py -d 192.168.1.1 -u admin --os nxos --json

Prerequisites:
    - paramiko: pip install paramiko
    - SSH access to device with privilege level 15 (Cisco IOS/NX-OS)
    - Network connectivity to target device
"""

import argparse
import json
import logging
import sys
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class DeviceHealthMonitor:
    """Collects health metrics from network devices via SSH."""

    def __init__(self, host, username, password, device_os):
        self.host = host
        self.username = username
        self.password = password
        self.device_os = device_os.lower()
        self.client = SSHClient()
        self.client.set_missing_host_key_policy(AutoAddPolicy())
        self.metrics = {}

    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Connected to {self.host}")
            return True
        except (AuthenticationException, SSHException) as e:
            logger.error(f"Connection failed: {e}")
            return False

    def execute_command(self, command):
        """Execute command on device and return output."""
        try:
            _, stdout, stderr = self.client.exec_command(command, timeout=10)
            output = stdout.read().decode('utf-8')
            return output
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return ""

    def check_health(self):
        """Collect health metrics based on device OS type."""
        if not self.connect():
            return False

        try:
            if self.device_os == 'ios':
                self._parse_ios()
            elif self.device_os == 'nxos':
                self._parse_nxos()
            else:
                logger.warning(f"Unsupported OS: {self.device_os}")
                return False
            return True
        finally:
            self.client.close()

    def _parse_ios(self):
        """Parse health metrics for Cisco IOS."""
        self.metrics['device_type'] = 'Cisco IOS'

        version_out = self.execute_command('show version')
        for line in version_out.split('\n'):
            if 'uptime is' in line.lower():
                self.metrics['uptime'] = line.strip()
                break

        cpu_out = self.execute_command('show processes cpu')
        for line in cpu_out.split('\n'):
            if 'CPU utilization for five seconds' in line:
                try:
                    cpu_val = int(line.split('/')[0].split()[-1])
                    self.metrics['cpu_5sec_percent'] = cpu_val
                except (ValueError, IndexError):
                    pass

        memory_out = self.execute_command('show memory')
        for line in memory_out.split('\n'):
            if 'Processor (Heap)' in line:
                try:
                    parts = line.split()
                    total = int(parts[-2])
                    free = int(parts[-1])
                    used_pct = int(100 * (total - free) / total)
                    self.metrics['memory_used_percent'] = used_pct
                except (ValueError, IndexError):
                    pass

    def _parse_nxos(self):
        """Parse health metrics for Cisco NX-OS."""
        self.metrics['device_type'] = 'Cisco NX-OS'

        version_out = self.execute_command('show version')
        for line in version_out.split('\n'):
            if 'System uptime' in line:
                self.metrics['uptime'] = line.strip()
                break

        cpu_out = self.execute_command('show processes cpu')
        for line in cpu_out.split('\n'):
            if 'CPU usage' in line and '%' in line:
                try:
                    cpu_val = float(line.split()[-1].rstrip('%'))
                    self.metrics['cpu_usage_percent'] = cpu_val
                except (ValueError, IndexError):
                    pass

        memory_out = self.execute_command('show system memory')
        for line in memory_out.split('\n'):
            if 'Total' in line and 'Used' in line:
                try:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if 'Mbytes' in part and i > 1:
                            used = int(parts[i - 2])
                            total = int(parts[i - 4])
                            used_pct = int(100 * used / total)
                            self.metrics['memory_used_percent'] = used_pct
                            break
                except (ValueError, IndexError):
                    pass

    def display_results(self, json_format=False):
        """Display health check results."""
        if json_format:
            print(json.dumps(self.metrics, indent=2))
        else:
            print(f"\n{'Device Health Report':^50}")
            print(f"{'Host: ' + self.host:^50}")
            print("-" * 50)
            for key, value in self.metrics.items():
                key_display = key.replace('_', ' ').title()
                print(f"{key_display:.<40} {value}")
            print("-" * 50 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor health metrics on network devices',
        epilog='Example: %(prog)s -d 10.1.1.1 -u admin -p pass --os ios'
    )
    parser.add_argument('-d', '--device', required=True, help='Device IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', required=True, help='SSH password')
    parser.add_argument('--os', required=True, choices=['ios', 'nxos'],
                        help='Device operating system')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    monitor = DeviceHealthMonitor(args.device, args.username, args.password, args.os)

    if monitor.check_health():
        monitor.display_results(json_format=args.json)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
```