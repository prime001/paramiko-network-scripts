```python
#!/usr/bin/env python3
"""
Device Health Monitor

Collects system health metrics (uptime, CPU, memory) from network devices via SSH.

Usage:
    python device_health_monitor.py -d 192.168.1.1 -u admin -p password [-o report.txt]

Prerequisites:
    - paramiko installed (pip install paramiko)
    - SSH access to target devices
    - Devices support 'show version', 'show processes cpu', 'show memory' commands
"""

import logging
import argparse
import sys
import re
from datetime import datetime
import paramiko


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DeviceHealthMonitor:
    def __init__(self, host, username, password, timeout=30):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = None
        self.metrics = {}

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, username=self.username, password=self.password,
                              timeout=self.timeout, look_for_keys=False, allow_agent=False)
            logger.info(f"Connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {self.host}")
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def disconnect(self):
        if self.client:
            self.client.close()

    def execute_command(self, cmd):
        try:
            _, stdout, stderr = self.client.exec_command(cmd, timeout=10)
            return stdout.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return ""

    def get_uptime(self):
        output = self.execute_command("show version")
        match = re.search(r'uptime is (.*?)(?:\n|$)', output, re.IGNORECASE)
        self.metrics['uptime'] = match.group(1).strip() if match else "Unknown"

    def get_cpu_usage(self):
        output = self.execute_command("show processes cpu sorted")
        match = re.search(r'CPU utilization for five seconds: (\d+)%', output)
        self.metrics['cpu'] = f"{match.group(1)}%" if match else "Unknown"

    def get_memory_usage(self):
        output = self.execute_command("show memory")
        match = re.search(r'Processor Pool Total:\s+(\d+)\s+(\d+)', output)
        if match:
            total, used = int(match.group(1)), int(match.group(2))
            percent = (used / total * 100) if total > 0 else 0
            self.metrics['memory'] = f"{percent:.1f}%"
        else:
            self.metrics['memory'] = "Unknown"

    def collect_metrics(self):
        if not self.connect():
            return False
        try:
            logger.info(f"Collecting metrics from {self.host}")
            self.get_uptime()
            self.get_cpu_usage()
            self.get_memory_usage()
            self.metrics['timestamp'] = datetime.now().isoformat()
            self.metrics['device'] = self.host
            return True
        finally:
            self.disconnect()

    def get_report(self):
        if not self.metrics:
            return "No metrics collected"
        return (f"\n{'='*50}\n"
                f"Device: {self.metrics['device']}\n"
                f"Time: {self.metrics['timestamp']}\n"
                f"{'='*50}\n"
                f"Uptime:  {self.metrics['uptime']}\n"
                f"CPU:     {self.metrics['cpu']}\n"
                f"Memory:  {self.metrics['memory']}\n"
                f"{'='*50}\n")


def main():
    parser = argparse.ArgumentParser(description="Monitor device health metrics")
    parser.add_argument('-d', '--device', required=True, help='Device IP/hostname')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', required=True, help='SSH password')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='SSH timeout')

    args = parser.parse_args()
    monitor = DeviceHealthMonitor(args.device, args.username, args.password, args.timeout)

    if not monitor.collect_metrics():
        logger.error("Failed to collect metrics")
        sys.exit(1)

    report = monitor.get_report()
    print(report)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to {args.output}")
        except Exception as e:
            logger.error(f"Failed to write report: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
```