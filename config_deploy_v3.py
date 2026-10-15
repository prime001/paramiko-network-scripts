```python
"""
Device Health Monitor

Purpose:
    Monitors system health metrics on network devices via SSH, including CPU,
    memory, and uptime. Useful for capacity planning and SLA monitoring.

Usage:
    python device_health_monitor.py --device 192.168.1.1 --username admin \
        --password secret --device-type cisco_ios

Prerequisites:
    - paramiko library installed
    - SSH access to target devices
    - Device user with sufficient privileges to execute show commands
"""

import argparse
import logging
import sys
from datetime import datetime
import paramiko
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DeviceHealthMonitor:
    """Monitor and report on network device system health."""

    COMMANDS = {
        'cisco_ios': {
            'cpu': 'show processes cpu | include CPU',
            'memory': 'show processes memory | include Memory',
            'uptime': 'show version | include uptime',
        },
        'arista_eos': {
            'cpu': 'show processes top CPU',
            'memory': 'show processes top memory',
            'uptime': 'show version | grep Uptime',
        },
    }

    def __init__(self, host, username, password, device_type='cisco_ios', port=22):
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.port = port
        self.client = None
        self.metrics = {}

    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                self.host, port=self.port, username=self.username,
                password=self.password, timeout=30, look_for_keys=False
            )
            logger.info(f"Connected to {self.host}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException) as e:
            logger.error(f"Connection error: {e}")
            return False

    def execute_command(self, cmd):
        """Execute command via SSH."""
        try:
            _, stdout, _ = self.client.exec_command(cmd, timeout=30)
            return stdout.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Command error: {e}")
            return None

    def parse_cpu(self, output):
        """Extract CPU percentage from output."""
        match = re.search(r'(\d+)%', output) if output else None
        return float(match.group(1)) if match else None

    def parse_memory(self, output):
        """Extract memory from output."""
        match = re.search(r'(\d+)K total', output) if output else None
        return int(match.group(1)) / 1024 if match else None

    def parse_uptime(self, output):
        """Extract uptime from output."""
        if not output:
            return None
        match = re.search(r'up\s+(.+?)(?:,|$)', output, re.IGNORECASE)
        return match.group(1).strip() if match else output.strip()[:50]

    def collect_metrics(self):
        """Collect all health metrics."""
        commands = self.COMMANDS.get(self.device_type, self.COMMANDS['cisco_ios'])
        self.metrics['device'] = self.host
        self.metrics['timestamp'] = datetime.now().isoformat()

        for metric, cmd in commands.items():
            output = self.execute_command(cmd)
            if output:
                if metric == 'cpu':
                    self.metrics['cpu'] = self.parse_cpu(output)
                elif metric == 'memory':
                    self.metrics['memory_mb'] = self.parse_memory(output)
                elif metric == 'uptime':
                    self.metrics['uptime'] = self.parse_uptime(output)
            logger.info(f"Collected {metric}")

        return self.metrics

    def report(self):
        """Print health report."""
        if not self.metrics:
            print("No metrics collected")
            return

        print(f"\nDevice Health Report - {self.metrics['device']}")
        print(f"Timestamp: {self.metrics['timestamp']}")
        print("-" * 50)

        if 'cpu' in self.metrics:
            cpu = self.metrics['cpu']
            status = "CRITICAL" if cpu > 80 else ("WARNING" if cpu > 60 else "OK")
            print(f"CPU: {cpu}% [{status}]")

        if 'memory_mb' in self.metrics:
            print(f"Memory: {self.metrics['memory_mb']:.2f} MB")

        if 'uptime' in self.metrics:
            print(f"Uptime: {self.metrics['uptime']}")

        print("-" * 50)

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
            logger.info("Disconnected")


def main():
    parser = argparse.ArgumentParser(description='Monitor device health metrics')
    parser.add_argument('--device', required=True, help='Device IP/hostname')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--device-type', default='cisco_ios', help='Device type')
    parser.add_argument('--port', type=int, default=22, help='SSH port')

    args = parser.parse_args()
    monitor = DeviceHealthMonitor(args.device, args.username, args.password, args.device_type, args.port)

    try:
        if not monitor.connect():
            sys.exit(1)
        monitor.collect_metrics()
        monitor.report()
    except KeyboardInterrupt:
        logger.info("Cancelled")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    finally:
        monitor.disconnect()


if __name__ == '__main__':
    main()
```