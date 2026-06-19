```python
"""
Device Health Monitor - SSH-based system health check for network devices.

Purpose:
    Collect and display health metrics (CPU, memory, temperature, uptime)
    from network devices via SSH using paramiko.

Usage:
    python device_health_monitor.py --host 192.168.1.1 --user admin --password pass

Prerequisites:
    - paramiko >= 2.7.0
    - Network devices accessible via SSH
    - User credentials with execute permissions
"""

import argparse
import logging
import paramiko
import re
import sys


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceHealthMonitor:
    """Monitor health metrics from network devices via SSH."""

    def __init__(self, host, username, password, port=22, timeout=30):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.ssh = None

    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logger.info(f"Connecting to {self.host}:{self.port}")
            self.ssh.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
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

    def execute_command(self, command):
        """Execute command and return output."""
        if not self.ssh:
            return None
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command, timeout=self.timeout)
            return stdout.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Command error: {e}")
            return None

    def get_metrics(self, custom_cmd=None):
        """Gather health metrics from device."""
        if not self.ssh:
            logger.error("Not connected")
            return {}

        command = custom_cmd or "show system resources"
        output = self.execute_command(command)
        if not output:
            return {}

        metrics = {}

        cpu_match = re.search(r'CPU.*?(\d+(?:\.\d+)?)\s*%', output, re.IGNORECASE)
        if cpu_match:
            metrics['CPU'] = f"{cpu_match.group(1)}%"

        mem_match = re.search(r'[Mm]emory.*?(\d+(?:\.\d+)?)\s*%', output, re.IGNORECASE)
        if mem_match:
            metrics['Memory'] = f"{mem_match.group(1)}%"

        uptime_match = re.search(r'[Uu]ptime[:\s]*([^\n]+)', output)
        if uptime_match:
            metrics['Uptime'] = uptime_match.group(1).strip()[:50]

        temp_match = re.search(r'[Tt]emperature.*?(\d+)\s*[°C]', output)
        if temp_match:
            metrics['Temperature'] = f"{temp_match.group(1)}°C"

        return metrics

    def disconnect(self):
        """Close SSH connection."""
        if self.ssh:
            self.ssh.close()
            logger.info(f"Disconnected from {self.host}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor network device health metrics',
        epilog='Example: python device_health_monitor.py --host 10.0.0.1 --user admin --password pass123'
    )
    parser.add_argument('--host', required=True, help='Device IP or hostname')
    parser.add_argument('--user', '--username', required=True, dest='username', help='SSH username')
    parser.add_argument('-p', '--password', required=True, help='SSH password')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout (default: 30)')
    parser.add_argument('--command', help='Custom command to execute')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    monitor = DeviceHealthMonitor(args.host, args.username, args.password, args.port, args.timeout)

    try:
        if not monitor.connect():
            sys.exit(1)

        metrics = monitor.get_metrics(args.command)

        if metrics:
            print(f"\nHealth Status for {args.host}:")
            print("=" * 50)
            for key, value in metrics.items():
                print(f"{key:<20} : {value}")
            print("=" * 50)
        else:
            logger.warning("No metrics gathered")

    except KeyboardInterrupt:
        logger.info("Cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    finally:
        monitor.disconnect()


if __name__ == "__main__":
    main()
```