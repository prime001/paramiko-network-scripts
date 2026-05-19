```python
"""
Device Log Collector and Aggregator

Connects to network devices via SSH, collects system logs, and aggregates
them for analysis and reporting. Supports filtering by severity level and
keyword search across multiple devices.

Prerequisites:
    - paramiko: pip install paramiko
    - SSH access to devices with valid credentials
    - Devices must support 'show log' or 'display log' command

Usage:
    python device_log_collector.py -d 192.168.1.1 -u admin -p password
    python device_log_collector.py -f devices.txt -s ERROR -o report.json
    python device_log_collector.py -d 10.0.0.5 -u admin -p pass -k "failure"
"""

import argparse
import json
import logging
import sys
from typing import List, Dict, Any

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceLogCollector:
    """SSH-based log collector for network devices."""

    def __init__(self, host: str, username: str, password: str, timeout: int = 10):
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
                self.host,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            logger.info(f"Connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {self.host}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH error connecting to {self.host}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}: {e}")
            return False

    def get_logs(self, lines: int = 100) -> List[str]:
        """Retrieve system logs from device via SSH."""
        if not self.client:
            logger.error("Not connected to device")
            return []

        try:
            _, stdout, _ = self.client.exec_command(f"show log tail {lines}")
            output = stdout.read().decode('utf-8', errors='ignore')
            return [line for line in output.strip().split('\n') if line]
        except Exception as e:
            logger.error(f"Failed to retrieve logs from {self.host}: {e}")
            return []

    def parse_logs(self, raw_logs: List[str]) -> List[Dict[str, Any]]:
        """Parse raw log lines into structured format."""
        parsed = []
        for line in raw_logs:
            severity = self._extract_severity(line)
            parsed.append({
                'raw': line,
                'severity': severity,
                'message': line
            })
        return parsed

    @staticmethod
    def _extract_severity(line: str) -> str:
        """Extract log severity level from log line."""
        line_upper = line.upper()
        for severity in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
            if severity in line_upper:
                return severity
        return 'INFO'

    def filter_logs(self, logs: List[Dict], severity: str = None,
                   search_text: str = None) -> List[Dict]:
        """Filter logs by severity and/or search keyword."""
        filtered = logs

        if severity:
            filtered = [l for l in filtered
                       if l['severity'] == severity.upper()]

        if search_text:
            filtered = [l for l in filtered
                       if search_text.lower() in l['raw'].lower()]

        return filtered

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
            logger.info(f"Disconnected from {self.host}")


def load_devices_from_file(filepath: str) -> List[str]:
    """Load list of device IPs/hostnames from file."""
    try:
        with open(filepath) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"Device file not found: {filepath}")
        return []


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-d', '--device', help='Device IP or hostname')
    parser.add_argument('-f', '--file', help='File with list of devices')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', required=True, help='SSH password')
    parser.add_argument('-l', '--lines', type=int, default=100,
                       help='Number of log lines to retrieve (default: 100)')
    parser.add_argument('-s', '--severity', help='Filter by severity (CRITICAL, ERROR, WARNING, INFO, DEBUG)')
    parser.add_argument('-k', '--keyword', help='Search logs for keyword')
    parser.add_argument('-o', '--output', help='Output file (JSON format)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='SSH timeout in seconds (default: 10)')

    args = parser.parse_args()

    if not args.device and not args.file:
        parser.error("Specify either --device or --file")

    devices = []
    if args.device:
        devices = [args.device]
    elif args.file:
        devices = load_devices_from_file(args.file)
        if not devices:
            return 1

    all_results = {}

    for device in devices:
        collector = DeviceLogCollector(
            device, args.username, args.password, args.timeout
        )

        if not collector.connect():
            all_results[device] = {'status': 'failed', 'error': 'Connection failed'}
            continue

        raw_logs = collector.get_logs(args.lines)
        parsed_logs = collector.parse_logs(raw_logs)
        filtered_logs = collector.filter_logs(
            parsed_logs, args.severity, args.keyword
        )

        all_results[device] = {
            'status': 'success',
            'total_logs': len(parsed_logs),
            'filtered_count': len(filtered_logs),
            'logs': filtered_logs
        }

        logger.info(
            f"{device}: {len(filtered_logs)}/{len(parsed_logs)} logs matching filters"
        )
        collector.disconnect()

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=2)
            logger.info(f"Results saved to {args.output}")
        except IOError as e:
            logger.error(f"Failed to write output file: {e}")
            return 1
    else:
        for device, data in all_results.items():
            print(f"\n{'='*70}")
            print(f"Device: {device} | Status: {data['status']}")
            if data['status'] == 'success':
                print(f"Logs: {data['filtered_count']}/{data['total_logs']}")
                print(f"{'='*70}")
                for log in data['logs'][:25]:
                    print(log['raw'])
            else:
                print(f"Error: {data.get('error', 'Unknown error')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```