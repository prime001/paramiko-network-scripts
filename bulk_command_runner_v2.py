```python
"""
Device System Resource Monitor

Retrieves system resource statistics from network devices via SSH.
Monitors CPU, memory, uptime, temperature, and version information.

Usage:
    python device_health_monitor.py -d 192.168.1.1 -u admin -p password
    python device_health_monitor.py -f devices.txt -u admin -p password

Prerequisites:
    - paramiko library installed (pip install paramiko)
    - SSH access to target devices
    - Network device running Cisco IOS/IOS-XE or compatible
    
Output:
    Terminal report with system health metrics for each device
"""

import paramiko
import argparse
import logging
import sys
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceHealthMonitor:
    """Monitor system resources on network devices via SSH."""
    
    def __init__(self, host, username, password, timeout=10):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ssh = None
        
    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(
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
        except paramiko.SSHException as e:
            logger.error(f"SSH error connecting to {self.host}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error connecting to {self.host}: {e}")
            return False
    
    def execute_command(self, command):
        """Execute command on device and return output."""
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command, timeout=self.timeout)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error and 'invalid' in error.lower():
                logger.warning(f"Command error: {error[:50]}")
            
            return output
        except Exception as e:
            logger.error(f"Command execution error on {self.host}: {e}")
            return None
    
    def get_uptime(self):
        """Retrieve device uptime."""
        output = self.execute_command("show version")
        if not output:
            return "N/A"
        
        for line in output.split('\n'):
            if 'uptime' in line.lower():
                return line.strip()
        return "Uptime not found"
    
    def get_cpu_usage(self):
        """Retrieve CPU utilization."""
        output = self.execute_command("show processes cpu sorted")
        if not output:
            return "N/A"
        
        for line in output.split('\n'):
            if 'CPU utilization' in line:
                return line.strip()
        return "CPU info not found"
    
    def get_memory_usage(self):
        """Retrieve memory statistics."""
        output = self.execute_command("show memory statistics")
        if not output:
            return "N/A"
        
        for line in output.split('\n'):
            if 'Processor' in line and 'memory' in line.lower():
                return line.strip()
        return "Memory info not found"
    
    def get_device_model(self):
        """Retrieve device model and version."""
        output = self.execute_command("show version | include Model Number")
        if output:
            return output.strip()
        return "Model info unavailable"
    
    def collect_health_data(self):
        """Collect all health metrics from device."""
        return {
            'host': self.host,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'uptime': self.get_uptime(),
            'cpu_usage': self.get_cpu_usage(),
            'memory_usage': self.get_memory_usage(),
            'device_model': self.get_device_model()
        }
    
    def close(self):
        """Close SSH connection."""
        if self.ssh:
            self.ssh.close()
            logger.info(f"Disconnected from {self.host}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor system resources on network devices'
    )
    parser.add_argument(
        '-d', '--device',
        help='Target device IP or hostname'
    )
    parser.add_argument(
        '-f', '--file',
        help='File containing list of devices (one per line)'
    )
    parser.add_argument(
        '-u', '--username',
        required=True,
        help='SSH username'
    )
    parser.add_argument(
        '-p', '--password',
        required=True,
        help='SSH password'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='SSH connection timeout in seconds'
    )
    
    args = parser.parse_args()
    
    if not args.device and not args.file:
        parser.error("Specify either -d/--device or -f/--file")
    
    devices = []
    if args.device:
        devices = [args.device]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                devices = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"File not found: {args.file}")
            sys.exit(1)
    
    results = []
    for device in devices:
        monitor = DeviceHealthMonitor(
            device,
            args.username,
            args.password,
            args.timeout
        )
        
        if monitor.connect():
            data = monitor.collect_health_data()
            results.append(data)
            
            print(f"\n--- Health Report: {device} ---")
            print(f"Timestamp: {data['timestamp']}")
            print(f"Uptime: {data['uptime']}")
            print(f"CPU Usage: {data['cpu_usage']}")
            print(f"Memory: {data['memory_usage']}")
            print(f"Model: {data['device_model']}")
            
            monitor.close()
        else:
            logger.error(f"Failed to monitor {device}")
    
    if results:
        logger.info(f"Successfully collected metrics from {len(results)} device(s)")
    else:
        logger.warning("No devices were successfully monitored")
        sys.exit(1)


if __name__ == "__main__":
    main()
```