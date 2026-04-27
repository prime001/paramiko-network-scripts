```python
#!/usr/bin/env python3
"""
Configuration Rollback Safety Validator

Compares device running configuration against a baseline backup, identifies
changes, and validates rollback safety before applying changes. Useful for
preventing configuration drift and ensuring emergency rollback procedures work.

Usage:
    python config_rollback_validator.py --device 192.168.1.1 --username admin \
        --password pass --baseline-file backup.conf

    python config_rollback_validator.py -d 10.0.0.5 -u admin -p pass \
        --baseline-file baseline.conf --generate-rollback

Prerequisites:
    - paramiko >= 2.11.0
    - Python 3.7+
    - SSH access to target device
    - Read access to running-config and ability to write files
    - Baseline configuration file from previous backup

Returns:
    0 - Configuration matches baseline
    1 - Configuration differs from baseline or validation failed
    2 - Connection or file error
"""

import argparse
import logging
import paramiko
import sys
import difflib
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConfigRollbackValidator:
    """Validates configuration rollback safety."""

    def __init__(self, host, username, password, timeout=15):
        """Initialize SSH connection."""
        self.host = host
        self.username = username
        self.timeout = timeout
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.client.connect(
                self.host,
                username=self.username,
                password=password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Connected to {self.host}")
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            raise

    def get_running_config(self):
        """Retrieve running configuration from device."""
        try:
            stdin, stdout, stderr = self.client.exec_command(
                "show running-config",
                timeout=self.timeout
            )
            config = stdout.read().decode('utf-8', errors='ignore')
            logger.info(f"Retrieved {len(config)} bytes of running configuration")
            return config
        except Exception as e:
            logger.error(f"Failed to retrieve running config: {e}")
            return None

    def load_baseline_config(self, filepath):
        """Load baseline configuration from file."""
        try:
            with open(filepath, 'r') as f:
                config = f.read()
            logger.info(f"Loaded baseline config from {filepath}")
            return config
        except FileNotFoundError:
            logger.error(f"Baseline file not found: {filepath}")
            return None
        except Exception as e:
            logger.error(f"Error reading baseline file: {e}")
            return None

    def compare_configs(self, current, baseline):
        """Compare running config with baseline."""
        current_lines = current.splitlines(keepends=True)
        baseline_lines = baseline.splitlines(keepends=True)
        
        diff = list(difflib.unified_diff(
            baseline_lines,
            current_lines,
            fromfile='Baseline',
            tofile='Running Config',
            lineterm=''
        ))
        
        return diff

    def identify_critical_removals(self, diff):
        """Identify if critical configuration lines were removed."""
        critical_keywords = [
            'ip address',
            'router ospf',
            'router bgp',
            'vlan',
            'spanning-tree',
            'access-list',
            'route-map'
        ]
        
        removals = []
        for line in diff:
            if line.startswith('-') and not line.startswith('---'):
                for keyword in critical_keywords:
                    if keyword in line.lower():
                        removals.append(line.strip())
        
        return removals

    def generate_rollback_commands(self, diff, device_type='cisco'):
        """Generate rollback commands from diff."""
        rollback_commands = []
        
        for line in diff:
            if line.startswith('+') and not line.startswith('+++'):
                config_line = line[1:].strip()
                if config_line:
                    rollback_commands.append(f"no {config_line}")
            elif line.startswith('-') and not line.startswith('---'):
                config_line = line[1:].strip()
                if config_line:
                    rollback_commands.append(config_line)
        
        return rollback_commands

    def save_diff_report(self, diff, filename):
        """Save diff report to file."""
        try:
            with open(filename, 'w') as f:
                f.writelines(diff)
            logger.info(f"Diff report saved to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save diff report: {e}")
            return False

    def validate_rollback_safety(self, current_config, baseline_config):
        """Validate that rollback is safe."""
        diff = self.compare_configs(current_config, baseline_config)
        critical_removals = self.identify_critical_removals(diff)
        
        if not diff:
            logger.info("Configuration matches baseline exactly")
            return True, "No changes detected", []
        
        if critical_removals:
            logger.warning(f"Found {len(critical_removals)} critical removals")
            for removal in critical_removals:
                logger.warning(f"  Critical removal: {removal}")
            return False, f"Critical configuration removed: {critical_removals}", diff
        
        logger.info(f"Configuration differs from baseline ({len(diff)} diff lines)")
        return True, "Configuration differs but safe to rollback", diff

    def close(self):
        """Close SSH connection."""
        self.client.close()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate configuration rollback safety",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument("--device", "-d", required=True, help="Device IP or hostname")
    parser.add_argument("--username", "-u", required=True, help="SSH username")
    parser.add_argument("--password", "-p", required=True, help="SSH password")
    parser.add_argument("--baseline-file", "-b", required=True, help="Baseline config file")
    parser.add_argument("--timeout", "-t", type=int, default=15, help="SSH timeout seconds")
    parser.add_argument("--generate-rollback", action="store_true", help="Generate rollback commands")
    parser.add_argument("--output-diff", help="Save diff to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        validator = ConfigRollbackValidator(
            args.device,
            args.username,
            args.password,
            args.timeout
        )
        
        current_config = validator.get_running_config()
        if not current_config:
            logger.error("Failed to retrieve running configuration")
            sys.exit(2)
        
        baseline_config = validator.load_baseline_config(args.baseline_file)
        if not baseline_config:
            logger.error("Failed to load baseline configuration")
            sys.exit(2)
        
        is_safe, message, diff = validator.validate_rollback_safety(
            current_config,
            baseline_config
        )
        
        logger.info(message)
        
        if args.output_diff and diff:
            validator.save_diff_report(diff, args.output_diff)
        
        if args.generate_rollback and diff:
            rollback_cmds = validator.generate_rollback_commands(diff)
            logger.info("\n=== Suggested Rollback Commands ===")
            logger.info("enter config mode and apply these commands:")
            for cmd in rollback_cmds:
                logger.info(f"  {cmd}")
        
        validator.close()
        
        sys.exit(0 if is_safe else 1)
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(2)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
```