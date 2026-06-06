```python
"""
Device Health Monitor

Purpose:
    Monitor network device health metrics (CPU, memory, uptime) via SSH using paramiko.
    Supports Cisco IOS and IOS-XE devices.

Usage:
    python device_health_monitor.py --device 192.168.1.1 --username admin --password secret
    python device_health_monitor.py -d 10.0.0.1 -u admin --key-file ~/.ssh/id_rsa

Prerequisites:
    - paramiko: pip install paramiko
    - Device SSH access enabled
    - User with read permissions to execute show commands
    - Device supports 'show version', 'show processes cpu', 'show memory'
"""

import argparse
import json
import logging
import re
import sys

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceHealthMonitor:
    """Monitor network device health via SSH."""

    def __init__(self, host, username, password=None, key_file=None, port=22, timeout=10):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.timeout = timeout
        self.client = None

    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if self.key_file:
                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_file,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
            else:
                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
            logger.info(f"Connected to {self.host}")
        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Connection error: {e}")
            raise

    def exec_cmd(self, command):
        """Execute command on device and return output."""
        if not self.client:
            return None
        try:
            _, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            return stdout.read().decode('utf-8')
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return None

    def get_uptime(self):
        """Extract uptime from device output."""
        output = self.exec_cmd('show version')
        if output:
            match = re.search(r'uptime is (.+)', output, re.IGNORECASE)
            return match.group(1).strip() if match else 'Unknown'
        return None

    def get_cpu(self):
        """Extract CPU utilization percentage."""
        output = self.exec_cmd('show processes cpu | include CPU utilization')
        if output:
            match = re.search(r'(\d+)%', output)
            return int(match.group(1)) if match else None
        return None

    def get_memory(self):
        """Extract memory utilization percentage."""
        output = self.exec_cmd('show memory')
        if output:
            match = re.search(r'Processor.*?(\d+)K\s+total,\s+(\d+)K\s+used', output)
            if match:
                total, used = int(match.group(1)), int(match.group(2))
                return round((used / total * 100), 2) if total > 0 else 0
        return None

    def collect(self):
        """Collect all health metrics."""
        try:
            self.connect()
            metrics = {
                'host': self.host,
                'uptime': self.get_uptime(),
                'cpu_percent': self.get_cpu(),
                'memory_percent': self.get_memory(),
                'status': 'success'
            }
        except Exception as e:
            metrics = {'host': self.host, 'status': 'failed', 'error': str(e)}
        finally:
            if self.client:
                self.client.close()
        return metrics


def format_output(metrics, fmt):
    """Format metrics for display."""
    if metrics['status'] == 'failed':
        return f"FAILED: {metrics.get('error', 'Unknown error')}"

    if fmt == 'json':
        return json.dumps(metrics, indent=2)

    lines = [f"Device: {metrics['host']}", '-' * 40]
    if metrics['uptime']:
        lines.append(f"Uptime: {metrics['uptime']}")
    if metrics['cpu_percent'] is not None:
        lines.append(f"CPU: {metrics['cpu_percent']}%")
    if metrics['memory_percent'] is not None:
        lines.append(f"Memory: {metrics['memory_percent']}%")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor network device health metrics via SSH'
    )
    parser.add_argument('-d', '--device', required=True, help='Device IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password')
    parser.add_argument('-k', '--key-file', help='SSH private key file path')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=10, help='Command timeout in seconds')
    parser.add_argument(
        '-o', '--output',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        parser.error('Either --password or --key-file must be provided')

    monitor = DeviceHealthMonitor(
        host=args.device,
        username=args.username,
        password=args.password,
        key_file=args.key_file,
        port=args.port,
        timeout=args.timeout
    )

    metrics = monitor.collect()
    output = format_output(metrics, args.output)
    print(output)

    return 0 if metrics['status'] == 'success' else 1


if __name__ == '__main__':
    sys.exit(main())
```