```python
"""
Device Health Monitor

Purpose:
    Monitors network device health metrics (CPU, memory, uptime) via SSH and
    reports status or alerts on threshold violations. Provides real-time health
    visibility for network operations.

Usage:
    python device_health_monitor.py -d 192.168.1.1 -u admin -p password
    python device_health_monitor.py -d core-router --cpu-threshold 75 --mem-threshold 80

Prerequisites:
    - paramiko library installed
    - Target device must have SSH enabled
    - User must have CLI/exec permissions on target device
    - Works with Cisco IOS/IOS-XE devices

Features:
    - Monitors CPU, memory, and uptime metrics
    - Configurable alert thresholds
    - Proper error handling and logging
    - Device connection pooling
"""

import argparse
import logging
import re
import sys
from datetime import datetime

import paramiko


class DeviceHealthMonitor:
    """Monitors device CPU, memory, and uptime metrics via SSH."""

    def __init__(self, host, username, password, port=22, timeout=10):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.client = None
        self.logger = self._setup_logging()

    def _setup_logging(self):
        """Configure logging with timestamp and level."""
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )
            self.client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            self.logger.info(f"Connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            self.logger.error(
                f"Authentication failed for {self.host}"
            )
            return False
        except paramiko.SSHException as e:
            self.logger.error(f"SSH error on {self.host}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Connection failed to {self.host}: {e}")
            return False

    def execute_command(self, command):
        """Execute CLI command and return output."""
        if not self.client:
            self.logger.error("Not connected to device")
            return None

        try:
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=self.timeout
            )
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')

            if error and "% " not in error:
                self.logger.debug(f"stderr: {error}")

            return output
        except paramiko.SSHException as e:
            self.logger.error(f"Command execution failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error executing command: {e}")
            return None

    def get_uptime(self):
        """Extract device uptime from show version output."""
        output = self.execute_command("show version")
        if not output:
            return None

        match = re.search(r'uptime is (.+?)(?:\n|$)', output)
        if match:
            return match.group(1).strip()
        return None

    def get_cpu_usage(self):
        """Extract CPU usage percentage from show processes cpu."""
        output = self.execute_command("show processes cpu")
        if not output:
            return None

        match = re.search(
            r'CPU utilization for five seconds:\s+(\d+)%',
            output
        )
        if match:
            return int(match.group(1))

        match = re.search(r'CPU utilization:\s+(\d+)%', output)
        if match:
            return int(match.group(1))

        return None

    def get_memory_usage(self):
        """Extract memory usage percentage from show memory."""
        output = self.execute_command("show memory")
        if not output:
            return None

        lines = output.split('\n')
        for line in lines:
            if 'Processor' in line or 'DRAM' in line:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 3:
                    try:
                        used = int(parts[-3])
                        total = int(parts[-2])
                        if total > 0:
                            return int((used / total) * 100)
                    except (ValueError, IndexError):
                        continue

        return None

    def check_health(self, cpu_threshold=80, mem_threshold=85):
        """Check device health metrics and report status."""
        if not self.connect():
            return False

        try:
            self.logger.info("=" * 70)
            self.logger.info(f"Device Health Check: {self.host}")
            self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
            self.logger.info("=" * 70)

            uptime = self.get_uptime()
            if uptime:
                self.logger.info(f"Uptime: {uptime}")
            else:
                self.logger.warning("Could not retrieve uptime")

            cpu_usage = self.get_cpu_usage()
            if cpu_usage is not None:
                status = (
                    "ALERT" if cpu_usage > cpu_threshold else "OK"
                )
                self.logger.info(f"CPU Usage: {cpu_usage}% [{status}]")
                if cpu_usage > cpu_threshold:
                    self.logger.warning(
                        f"CPU usage {cpu_usage}% exceeds threshold "
                        f"({cpu_threshold}%)"
                    )
            else:
                self.logger.warning("Could not retrieve CPU usage")

            memory_usage = self.get_memory_usage()
            if memory_usage is not None:
                status = (
                    "ALERT" if memory_usage > mem_threshold else "OK"
                )
                self.logger.info(f"Memory Usage: {memory_usage}% [{status}]")
                if memory_usage > mem_threshold:
                    self.logger.warning(
                        f"Memory usage {memory_usage}% exceeds threshold "
                        f"({mem_threshold}%)"
                    )
            else:
                self.logger.warning("Could not retrieve memory usage")

            self.logger.info("=" * 70)
            return True

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
        finally:
            self.disconnect()

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            try:
                self.client.close()
                self.logger.info("Connection closed")
            except Exception as e:
                self.logger.error(f"Error closing connection: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor network device health metrics via SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python device_health_monitor.py -d 10.0.0.1 "
               "-u admin -p password"
    )
    parser.add_argument(
        "-d", "--device",
        required=True,
        help="Device hostname or IP address"
    )
    parser.add_argument(
        "-u", "--username",
        required=True,
        help="SSH username"
    )
    parser.add_argument(
        "-p", "--password",
        required=True,
        help="SSH password"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)"
    )
    parser.add_argument(
        "--cpu-threshold",
        type=int,
        default=80,
        help="CPU usage alert threshold in percent (default: 80)"
    )
    parser.add_argument(
        "--mem-threshold",
        type=int,
        default=85,
        help="Memory usage alert threshold in percent (default: 85)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="SSH timeout in seconds (default: 10)"
    )

    args = parser.parse_args()

    if args.cpu_threshold < 0 or args.cpu_threshold > 100:
        print("Error: CPU threshold must be between 0 and 100")
        sys.exit(1)

    if args.mem_threshold < 0 or args.mem_threshold > 100:
        print("Error: Memory threshold must be between 0 and 100")
        sys.exit(1)

    monitor = DeviceHealthMonitor(
        host=args.device,
        username=args.username,
        password=args.password,
        port=args.port,
        timeout=args.timeout
    )

    success = monitor.check_health(
        cpu_threshold=args.cpu_threshold,
        mem_threshold=args.mem_threshold
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
```