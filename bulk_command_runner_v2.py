```python
"""
Device Configuration Validator

Validates critical device configurations against best practices.
Connects via SSH, executes validation commands, and reports configuration issues.

Usage:
    python config_validator.py -d 192.168.1.1 -u admin -p password
    python config_validator.py -d 192.168.1.1 -u admin -k ~/.ssh/id_rsa

Prerequisites:
    - Device must support SSH access
    - paramiko library: pip install paramiko
    - Device must support standard show commands
"""

import paramiko
import logging
import argparse
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates device configuration compliance with best practices."""

    def __init__(self, host, username, password=None, key_file=None,
                 timeout=10, port=22):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.port = port
        self.client = None
        self.issues = []

    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if self.key_file:
                self.client.connect(
                    self.host, port=self.port, username=self.username,
                    key_filename=self.key_file, timeout=self.timeout,
                    look_for_keys=False
                )
            else:
                self.client.connect(
                    self.host, port=self.port, username=self.username,
                    password=self.password, timeout=self.timeout
                )
            logger.info(f"Connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            logger.error("Authentication failed")
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def run_command(self, cmd):
        """Execute command on device and return output."""
        try:
            stdin, stdout, stderr = self.client.exec_command(cmd,
                                                              timeout=self.timeout)
            return stdout.read().decode('utf-8')
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return ""

    def check_hostname(self):
        """Verify hostname is configured."""
        output = self.run_command("show running-config | include hostname")
        if not output.strip():
            self.issues.append("CRITICAL: Hostname not configured")

    def check_dns_servers(self):
        """Verify DNS servers are configured."""
        output = self.run_command("show running-config | include ip name-server")
        if not output.strip():
            self.issues.append("WARNING: No DNS servers configured")

    def check_syslog(self):
        """Verify logging/syslog is configured."""
        output = self.run_command("show running-config | include logging")
        if not output.strip():
            self.issues.append("WARNING: No syslog servers configured")

    def check_ntp(self):
        """Verify NTP is configured."""
        output = self.run_command("show running-config | include ntp")
        if not output.strip():
            self.issues.append("WARNING: No NTP configured")

    def check_interfaces_down(self):
        """Identify unexpectedly down interfaces."""
        output = self.run_command("show interface brief")
        down_count = output.count("down")
        if down_count > 0:
            self.issues.append(f"INFO: {down_count} interfaces down")

    def check_spanning_tree(self):
        """Verify spanning tree is running."""
        output = self.run_command("show spanning-tree root")
        if "disabled" in output.lower():
            self.issues.append("WARNING: Spanning tree disabled")

    def validate(self):
        """Run all validation checks."""
        logger.info("Starting configuration validation")
        self.check_hostname()
        self.check_dns_servers()
        self.check_syslog()
        self.check_ntp()
        self.check_interfaces_down()
        self.check_spanning_tree()
        return self.issues

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
            logger.info("Disconnected")


def main():
    parser = argparse.ArgumentParser(
        description='Validate device configuration best practices'
    )
    parser.add_argument('-d', '--device', required=True,
                        help='Device IP or hostname')
    parser.add_argument('-u', '--username', required=True,
                        help='SSH username')
    parser.add_argument('-p', '--password',
                        help='SSH password')
    parser.add_argument('-k', '--key-file',
                        help='SSH private key file path')
    parser.add_argument('--port', type=int, default=22,
                        help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Command timeout in seconds (default: 10)')

    args = parser.parse_args()

    if not args.password and not args.key_file:
        logger.error("Provide either --password or --key-file")
        sys.exit(1)

    validator = ConfigValidator(
        host=args.device,
        username=args.username,
        password=args.password,
        key_file=args.key_file,
        timeout=args.timeout,
        port=args.port
    )

    if not validator.connect():
        sys.exit(1)

    try:
        issues = validator.validate()

        print(f"\n{'='*70}")
        print(f"Configuration Validation Report: {args.device}")
        print(f"{'='*70}")

        if issues:
            print(f"\nFindings ({len(issues)}):\n")
            for issue in issues:
                prefix = issue.split(':')[0]
                symbol = "✓" if prefix == "INFO" else "⚠" if prefix == "WARNING" else "✗"
                print(f"  {symbol} {issue}")
        else:
            print("\n✓ No configuration issues detected")

        print(f"\n{'='*70}\n")
        sys.exit(0 if not any("CRITICAL" in i for i in issues) else 1)
    finally:
        validator.disconnect()


if __name__ == "__main__":
    main()
```