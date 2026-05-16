```python
"""
Device Configuration Auditor - Verify network devices comply with baseline requirements.

Purpose:
    Connects to network devices via SSH and audits configuration for required settings
    such as NTP, SNMP, syslog, and logging. Generates a compliance report.

Usage:
    python device_config_auditor.py --host 192.168.1.1 --username admin \
        --password <password> --checks ntp,snmp,syslog

Prerequisites:
    - paramiko library installed (pip install paramiko)
    - SSH access to target devices
    - Valid credentials with read access to device config

Author: Network Automation Portfolio
"""

import argparse
import logging
import sys
from typing import Dict, List, Tuple

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConfigAuditor:
    """Audits device configuration for compliance with baseline requirements."""

    CHECKS = {
        'ntp': [
            'ntp server',
            'ntp authenticate',
        ],
        'snmp': [
            'snmp-server community',
            'snmp-server trap-source',
        ],
        'syslog': [
            'logging host',
            'logging source-interface',
        ],
        'logging': [
            'logging buffered',
            'logging console',
        ],
        'ssh': [
            'ip ssh version 2',
            'transport input ssh',
        ]
    }

    def __init__(self, host: str, username: str, password: str, timeout: int = 10):
        """Initialize SSH client and connection parameters."""
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.config_lines = []

    def connect(self) -> bool:
        """Establish SSH connection to device."""
        try:
            logger.info(f"Connecting to {self.host}...")
            self.client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                banner_timeout=15
            )
            logger.info(f"Successfully connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {self.host}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH error connecting to {self.host}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to {self.host}: {e}")
            return False

    def get_config(self) -> bool:
        """Retrieve running configuration from device."""
        try:
            _, stdout, stderr = self.client.exec_command('show run')
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            if error and 'invalid command' in error.lower():
                logger.warning(f"Device {self.host} may not support 'show run'")
                return False

            self.config_lines = output.split('\n')
            logger.info(f"Retrieved {len(self.config_lines)} config lines")
            return True
        except Exception as e:
            logger.error(f"Failed to retrieve config: {e}")
            return False

    def audit_check(self, check_name: str) -> Tuple[str, bool, List[str]]:
        """Audit a specific configuration check."""
        required_keywords = self.CHECKS.get(check_name, [])

        if not required_keywords:
            return check_name, False, ["Unknown check"]

        found_items = []
        for keyword in required_keywords:
            for line in self.config_lines:
                if keyword.lower() in line.lower():
                    found_items.append(line.strip())
                    break

        is_compliant = len(found_items) == len(required_keywords)
        return check_name, is_compliant, found_items

    def run_audit(self, checks: List[str]) -> Dict[str, Dict]:
        """Run all requested configuration audits."""
        results = {}

        if not self.connect():
            return results

        if not self.get_config():
            self.client.close()
            return results

        for check in checks:
            if check in self.CHECKS:
                check_name, is_compliant, items = self.audit_check(check)
                results[check_name] = {
                    'compliant': is_compliant,
                    'found_items': items,
                    'required_count': len(self.CHECKS[check])
                }
            else:
                logger.warning(f"Unknown check: {check}")

        self.client.close()
        return results

    def print_report(self, results: Dict[str, Dict]) -> None:
        """Print formatted compliance report."""
        if not results:
            print("No audit results to report.")
            return

        print(f"\n{'='*60}")
        print(f"Configuration Audit Report - {self.host}")
        print(f"{'='*60}\n")

        compliant_count = sum(1 for r in results.values() if r['compliant'])
        total_checks = len(results)

        for check_name, result in results.items():
            status = "✓ PASS" if result['compliant'] else "✗ FAIL"
            print(f"{check_name:15} {status:10} ({len(result['found_items'])}/{result['required_count']} items)")
            for item in result['found_items']:
                print(f"  └─ {item[:70]}")

        print(f"\n{'='*60}")
        print(f"Summary: {compliant_count}/{total_checks} checks passed")
        print(f"{'='*60}\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Audit network device configuration compliance"
    )
    parser.add_argument('--host', required=True, help='Target device IP or hostname')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument(
        '--checks',
        default='ntp,snmp,logging',
        help='Comma-separated list of checks to run (default: ntp,snmp,logging)'
    )
    parser.add_argument('--timeout', type=int, default=10, help='SSH timeout in seconds')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    checks = [c.strip() for c in args.checks.split(',')]

    auditor = ConfigAuditor(
        host=args.host,
        username=args.username,
        password=args.password,
        timeout=args.timeout
    )

    results = auditor.run_audit(checks)
    auditor.print_report(results)

    if results and not all(r['compliant'] for r in results.values()):
        sys.exit(1)


if __name__ == '__main__':
    main()
```