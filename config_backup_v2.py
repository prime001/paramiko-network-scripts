```python
#!/usr/bin/env python3
"""
Device Config Change Detector.

Monitors network device configurations for unauthorized changes.
Compares running config against a stored baseline to identify differences.

Usage:
    python device_config_change_detector.py 192.168.1.1 \
        --username admin --baseline baseline.json --action detect

Prerequisites:
    - paramiko library
    - Network devices accessible via SSH
"""

import logging
import argparse
import hashlib
import json
from pathlib import Path
from datetime import datetime
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('config_changes.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class ConfigChangeDetector:
    """Detect configuration changes on network devices via SSH."""

    def __init__(self, device, username, password=None, timeout=10):
        self.device = device
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        """Establish SSH connection."""
        try:
            self.ssh.connect(
                self.device, username=self.username, password=self.password,
                timeout=self.timeout, look_for_keys=True, allow_agent=True
            )
            logger.info(f"Connected to {self.device}")
            return True
        except (AuthenticationException, SSHException) as e:
            logger.error(f"Connection failed for {self.device}: {e}")
            return False

    def get_running_config(self):
        """Retrieve running configuration."""
        try:
            _, stdout, stderr = self.ssh.exec_command("show running-config")
            config = stdout.read().decode('utf-8')
            if stderr.read().decode('utf-8'):
                logger.warning("Command produced stderr output")
            return config
        except Exception as e:
            logger.error(f"Error retrieving config: {e}")
            return None

    def compute_hash(self, config):
        """Compute SHA-256 hash of configuration."""
        return hashlib.sha256(config.encode()).hexdigest()

    def detect_changes(self, baseline_path):
        """Compare running config against baseline."""
        current_config = self.get_running_config()
        if not current_config:
            return False

        current_hash = self.compute_hash(current_config)
        baseline = self._load_baseline(baseline_path)

        if not baseline or current_hash == baseline.get('hash'):
            logger.info(f"No changes detected on {self.device}")
            return False

        logger.warning(f"Configuration change detected on {self.device}")
        logger.warning(
            f"Previous hash: {baseline.get('hash')}, Current: {current_hash}"
        )
        return True

    def _load_baseline(self, baseline_path):
        """Load baseline metadata."""
        try:
            with open(baseline_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Baseline load error: {e}")
            return None

    def update_baseline(self, baseline_path):
        """Update baseline with current configuration."""
        config = self.get_running_config()
        if not config:
            return False

        baseline_data = {
            'device': self.device,
            'hash': self.compute_hash(config),
            'timestamp': datetime.now().isoformat(),
            'lines': len(config.split('\n'))
        }

        try:
            Path(baseline_path).parent.mkdir(parents=True, exist_ok=True)
            with open(baseline_path, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            logger.info(f"Baseline updated: {baseline_path}")
            return True
        except IOError as e:
            logger.error(f"Baseline write error: {e}")
            return False

    def disconnect(self):
        """Close SSH connection."""
        self.ssh.close()


def main():
    parser = argparse.ArgumentParser(
        description='Detect configuration changes on network devices'
    )
    parser.add_argument('device', help='Target device IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password')
    parser.add_argument('-b', '--baseline', required=True,
                        help='Baseline configuration file path')
    parser.add_argument('-a', '--action', choices=['detect', 'update'],
                        default='detect', help='Action: detect or update')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='SSH connection timeout in seconds')

    args = parser.parse_args()
    detector = ConfigChangeDetector(
        args.device, args.username, args.password, args.timeout
    )

    try:
        if not detector.connect():
            return 1

        if args.action == 'detect':
            changed = detector.detect_changes(args.baseline)
            return 1 if changed else 0
        else:
            success = detector.update_baseline(args.baseline)
            return 0 if success else 1
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 130
    finally:
        detector.disconnect()


if __name__ == '__main__':
    exit(main())
```