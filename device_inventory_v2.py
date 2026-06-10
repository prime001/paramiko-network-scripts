```python
"""
Network Device Health Status Checker

Connects to network devices via SSH to collect and report health metrics
including CPU usage, memory utilization, and system uptime. Useful for
monitoring device resource health and alerting on threshold violations.

Usage:
    python health_checker.py --device 192.168.1.1 --username admin --password secret
    python health_checker.py -d 10.0.0.5 -u netadmin -p pass123 --cpu-threshold 80

Prerequisites:
    - paramiko: pip install paramiko
    - SSH access to target device with appropriate credentials
    - Device must support 'show version' and 'show processes' commands
    - Works with Cisco IOS/IOS-XE, Arista, and similar platforms
"""

import argparse
import logging
import sys
import paramiko
import re
from typing import Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceHealthChecker:
    def __init__(self, host: str, username: str, password: str, timeout: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ssh_client = None

    def connect(self) -> bool:
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Successfully connected to {self.host}")
            return True
        except paramiko.AuthenticationException:
            logger.error("SSH authentication failed - check credentials")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH connection failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def execute_command(self, command: str) -> Optional[str]:
        if not self.ssh_client:
            return None
        try:
            _, stdout, stderr = self.ssh_client.exec_command(command, timeout=self.timeout)
            output = stdout.read().decode('utf-8')
            err = stderr.read().decode('utf-8')
            if err and 'invalid' in err.lower():
                logger.warning(f"Command not supported: {command}")
                return None
            return output
        except paramiko.SSHException as e:
            logger.error(f"Command execution failed: {e}")
            return None

    def get_uptime(self) -> Optional[str]:
        output = self.execute_command("show version")
        if not output:
            return None
        for line in output.split('\n'):
            if 'uptime' in line.lower():
                return line.strip()
        return None

    def get_cpu_usage(self) -> Optional[Tuple[float, str]]:
        output = self.execute_command("show processes cpu")
        if not output:
            return None
        for line in output.split('\n'):
            match = re.search(r'(\d+\.?\d*)\s*%', line)
            if match and any(x in line.lower() for x in ['cpu', 'five']):
                return float(match.group(1)), line.strip()
        return None

    def get_memory_usage(self) -> Optional[Tuple[float, str]]:
        output = self.execute_command("show processes memory")
        if not output:
            return None
        for line in output.split('\n'):
            match = re.search(r'(\d+\.?\d*)\s*%', line)
            if match and any(x in line.lower() for x in ['memory', 'allocated']):
                return float(match.group(1)), line.strip()
        return None

    def print_report(self, cpu_threshold: int = 85, mem_threshold: int = 90) -> None:
        print("\n" + "="*70)
        print(f"Device Health Report: {self.host}")
        print("="*70 + "\n")

        uptime = self.get_uptime()
        print(f"Uptime:        {uptime or 'N/A'}")

        cpu_data = self.get_cpu_usage()
        if cpu_data:
            cpu_val, cpu_line = cpu_data
            alert = " ⚠️  ALERT" if cpu_val > cpu_threshold else ""
            print(f"CPU Usage:     {cpu_val:.2f}%{alert}")
        else:
            print("CPU Usage:     N/A")

        mem_data = self.get_memory_usage()
        if mem_data:
            mem_val, mem_line = mem_data
            alert = " ⚠️  ALERT" if mem_val > mem_threshold else ""
            print(f"Memory Usage:  {mem_val:.2f}%{alert}")
        else:
            print("Memory Usage:  N/A")

        print("\n" + "="*70 + "\n")

    def disconnect(self) -> None:
        if self.ssh_client:
            self.ssh_client.close()
            logger.info("Disconnected from device")


def main():
    parser = argparse.ArgumentParser(
        description="Check health metrics on network devices"
    )
    parser.add_argument(
        '--device', '-d',
        required=True,
        help='Target device IP address or hostname'
    )
    parser.add_argument(
        '--username', '-u',
        required=True,
        help='SSH username for authentication'
    )
    parser.add_argument(
        '--password', '-p',
        required=True,
        help='SSH password for authentication'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=10,
        help='SSH connection timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '--cpu-threshold',
        type=int,
        default=85,
        help='CPU alert threshold percentage (default: 85)'
    )
    parser.add_argument(
        '--memory-threshold',
        type=int,
        default=90,
        help='Memory alert threshold percentage (default: 90)'
    )

    args = parser.parse_args()

    checker = DeviceHealthChecker(
        args.device,
        args.username,
        args.password,
        args.timeout
    )

    try:
        if not checker.connect():
            sys.exit(1)
        checker.print_report(args.cpu_threshold, args.memory_threshold)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        checker.disconnect()


if __name__ == "__main__":
    main()
```