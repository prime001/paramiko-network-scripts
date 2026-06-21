```python
"""
NTP Status Checker

Verifies NTP configuration and synchronization status across network devices.
Collects NTP peer information and validates clock synchronization.

Usage:
    python ntp_status_checker.py --device 192.168.1.1 --username admin
    python ntp_status_checker.py --devices devices.txt --cred-file creds.txt
    python ntp_status_checker.py --device 192.168.1.1 --username admin --output report.csv

Prerequisites:
    - paramiko
    - SSH access to network devices
"""

import argparse
import csv
import logging
import sys
from datetime import datetime
from getpass import getpass

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NTPStatusChecker:
    def __init__(self, host, username, password, timeout=10):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = None

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {self.host}")
            return False
        except Exception as e:
            logger.error(f"Connection error to {self.host}: {e}")
            return False

    def execute_command(self, command):
        if not self.client:
            return None
        try:
            stdin, stdout, stderr = self.client.exec_command(
                command, timeout=self.timeout
            )
            output = stdout.read().decode('utf-8', errors='ignore')
            return output if output else stderr.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Command execution error on {self.host}: {e}")
            return None

    def check_ntp_status(self):
        result = {
            'device': self.host,
            'reachable': False,
            'synchronized': False,
            'stratum': 'N/A',
            'peer_count': 0,
            'errors': []
        }

        version_output = self.execute_command('show version')
        if not version_output:
            result['errors'].append('Device unreachable')
            return result

        result['reachable'] = True

        ntp_status = self.execute_command('show ntp status')
        if ntp_status:
            result['synchronized'] = 'synchronized' in ntp_status.lower()
            result['stratum'] = self._parse_stratum(ntp_status)
            if 'unsynchronized' in ntp_status.lower():
                result['errors'].append('Clock unsynchronized')
        else:
            result['errors'].append('Failed to retrieve NTP status')

        ntp_assoc = self.execute_command('show ntp associations')
        if ntp_assoc:
            peers = self._parse_ntp_peers(ntp_assoc)
            result['peer_count'] = len(peers)

        return result

    def _parse_stratum(self, output):
        for line in output.split('\n'):
            if 'stratum' in line.lower():
                parts = line.split(':')
                if len(parts) > 1:
                    return parts[1].strip().split()[0]
        return 'N/A'

    def _parse_ntp_peers(self, output):
        peers = []
        for line in output.split('\n'):
            line = line.strip()
            if line and not line.startswith('address') and '.' in line:
                addr = line.split()[0].lstrip('*+ -o x .')
                if '.' in addr:
                    peers.append(addr)
        return peers

    def disconnect(self):
        if self.client:
            self.client.close()


def load_devices_from_file(filename):
    devices = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    devices.append(line)
        return devices
    except FileNotFoundError:
        logger.error(f"Device file not found: {filename}")
        return []


def load_credentials_from_file(filename):
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            username = lines[0].strip() if len(lines) > 0 else None
            password = lines[1].strip() if len(lines) > 1 else None
            return username, password
    except FileNotFoundError:
        logger.error(f"Credentials file not found: {filename}")
        return None, None


def save_report(results, filename):
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'device', 'reachable', 'synchronized', 'stratum', 'peer_count', 'errors'
            ])
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'device': result['device'],
                    'reachable': result['reachable'],
                    'synchronized': result['synchronized'],
                    'stratum': result['stratum'],
                    'peer_count': result['peer_count'],
                    'errors': '; '.join(result['errors']) if result['errors'] else 'None'
                })
        logger.info(f"Report saved to {filename}")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Check NTP status on network devices'
    )
    parser.add_argument('--device', help='Single device IP/hostname')
    parser.add_argument('--devices', help='File with device list (one per line)')
    parser.add_argument('--username', '-u', help='SSH username')
    parser.add_argument('--password', '-p', help='SSH password')
    parser.add_argument('--cred-file', help='Credentials file (user on line 1, pass on line 2)')
    parser.add_argument('--timeout', type=int, default=10, help='SSH timeout (default: 10s)')
    parser.add_argument('--output', help='Save report to CSV file')

    args = parser.parse_args()

    devices = []
    if args.device:
        devices = [args.device]
    elif args.devices:
        devices = load_devices_from_file(args.devices)
    else:
        parser.error('Specify --device or --devices')

    if not devices:
        logger.error('No devices specified')
        sys.exit(1)

    username, password = args.username, args.password
    if args.cred_file:
        username, password = load_credentials_from_file(args.cred_file)

    if not username:
        username = input('Enter username: ')
    if not password:
        password = getpass('Enter password: ')

    results = []
    for device in devices:
        logger.info(f"Checking {device}")
        checker = NTPStatusChecker(device, username, password, args.timeout)

        if checker.connect():
            result = checker.check_ntp_status()
            results.append(result)
            checker.disconnect()
        else:
            results.append({
                'device': device,
                'reachable': False,
                'synchronized': False,
                'stratum': 'N/A',
                'peer_count': 0,
                'errors': ['Connection failed']
            })

    print('\n' + '=' * 70)
    print('NTP Status Summary')
    print('=' * 70)
    for result in results:
        status = 'GOOD' if result['synchronized'] else 'BAD'
        print(f"{result['device']:20} | {status:4} | Stratum: {result['stratum']:3} | Peers: {result['peer_count']}")
        for error in result['errors']:
            print(f"  {error}")
    print('=' * 70 + '\n')

    if args.output:
        save_report(results, args.output)


if __name__ == '__main__':
    main()
```