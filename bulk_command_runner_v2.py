#!/usr/bin/env python3
"""
Device Configuration Template Validator

Validates that a device's running configuration matches an expected configuration
template. Useful for compliance checking and configuration auditing.

Purpose:
    - Compare device running config against a template
    - Identify missing or mismatched configuration lines
    - Support partial line matching and variable substitution
    - Generate compliance reports

Usage:
    python config_validator.py -d 192.168.1.1 -u admin -p password -t template.cfg
    python config_validator.py -d device.example.com -u admin -k ~/.ssh/id_rsa -t compliance.txt --strict

Prerequisites:
    - Device must be accessible via SSH
    - paramiko library installed: pip install paramiko
    - Template file with expected configuration (one line per rule)
    - Valid SSH credentials or key-based auth
"""

import argparse
import logging
import sys
import paramiko
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates device config against a template."""

    def __init__(self, host, username, password=None, key_path=None, port=22):
        """Initialize SSH client."""
        self.host = host
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        """Establish SSH connection."""
        try:
            if self.key_path:
                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_path,
                    timeout=10
                )
            else:
                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=10
                )
            logger.info(f"Connected to {self.host}")
            return True
        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed: {e}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH error: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def get_running_config(self, command="show running-config"):
        """Retrieve running configuration from device."""
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            config = stdout.read().decode('utf-8', errors='ignore')
            if stderr.read():
                logger.warning("Errors during config retrieval")
            logger.info(f"Retrieved config ({len(config)} bytes)")
            return config
        except Exception as e:
            logger.error(f"Failed to get running config: {e}")
            return None

    def validate_config(self, running_config, template_lines, strict=False):
        """Validate running config against template rules."""
        results = {
            'matched': [],
            'missing': []
        }

        # Normalize config for comparison
        config_lines = [line.strip() for line in running_config.split('\n')]
        config_lower = [line.lower() for line in config_lines]

        for template_line in template_lines:
            template_line = template_line.strip()
            if not template_line or template_line.startswith('#'):
                continue

            template_lower = template_line.lower()

            # Check for exact match (case-insensitive)
            if template_lower in config_lower:
                results['matched'].append(template_line)
                logger.debug(f"✓ Found: {template_line}")
            # Check for partial match (substring) in non-strict mode
            elif not strict and any(template_lower in cl for cl in config_lower):
                results['matched'].append(template_line)
                logger.debug(f"✓ Found (partial): {template_line}")
            else:
                results['missing'].append(template_line)
                logger.warning(f"✗ Missing: {template_line}")

        return results

    def close(self):
        """Close SSH connection."""
        self.client.close()
        logger.info("Connection closed")

    def print_report(self, results):
        """Print validation report."""
        total = len(results['matched']) + len(results['missing'])
        match_pct = (len(results['matched']) / total * 100) if total > 0 else 0

        print(f"\n{'='*60}")
        print(f"Configuration Validation Report: {self.host}")
        print(f"{'='*60}")
        print(f"Matched:  {len(results['matched'])}/{total} ({match_pct:.1f}%)")
        print(f"Missing:  {len(results['missing'])}/{total}")

        if results['missing']:
            print(f"\n{'Missing Configuration Lines:'}")
            print("-" * 60)
            for line in results['missing']:
                print(f"  ✗ {line}")

        print(f"{'='*60}\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-d', '--device', required=True, help='Device IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password (use -k for key auth)')
    parser.add_argument('-k', '--key', help='Path to SSH private key')
    parser.add_argument('-t', '--template', required=True, help='Template config file path')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--strict', action='store_true', help='Require exact line matches')
    parser.add_argument('-c', '--command', default='show running-config',
                        help='Command to retrieve config (default: show running-config)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.password and not args.key:
        logger.error("Provide either password (-p) or key path (-k)")
        return 1

    try:
        template_path = Path(args.template)
        template_lines = template_path.read_text().split('\n')
        logger.info(f"Loaded template: {args.template} ({len(template_lines)} lines)")
    except Exception as e:
        logger.error(f"Failed to load template: {e}")
        return 1

    validator = ConfigValidator(
        host=args.device,
        username=args.username,
        password=args.password,
        key_path=args.key,
        port=args.port
    )

    if not validator.connect():
        return 1

    running_config = validator.get_running_config(args.command)
    if not running_config:
        validator.close()
        return 1

    results = validator.validate_config(running_config, template_lines, args.strict)
    validator.print_report(results)
    validator.close()

    return 0 if not results['missing'] else 1


if __name__ == '__main__':
    sys.exit(main())