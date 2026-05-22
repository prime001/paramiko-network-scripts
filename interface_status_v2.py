```python
"""
Device Health Check Script

Connects to network devices via SSH and retrieves CPU, memory, and temperature
metrics to assess device health. Supports Cisco IOS, IOS-XE, and Arista EOS.

Prerequisites:
  - paramiko library: pip install paramiko
  - Network device SSH access with appropriate credentials
  - Device must respond to health check commands (show processes, show system)

Usage:
  python device_health_check.py --host 192.168.1.1 --username admin --password pass
  python device_health_check.py --host 192.168.1.1 --username admin --key /path/to/key
  python device_health_check.py --host 192.168.1.1 --username admin --password pass --device-type ios
"""

import argparse
import logging
import sys
from typing import Dict, Optional

import paramiko


def setup_logging(verbose: bool = False) -> None:
    """Configure logging output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def connect_device(host: str, username: str, password: Optional[str] = None,
                   key_file: Optional[str] = None, port: int = 22,
                   timeout: int = 10) -> paramiko.SSHClient:
    """
    Establish SSH connection to network device.
    
    Args:
        host: Device IP or hostname
        username: SSH username
        password: SSH password (optional if using key)
        key_file: Path to private key file (optional)
        port: SSH port
        timeout: Connection timeout in seconds
        
    Returns:
        Connected paramiko SSHClient object
        
    Raises:
        paramiko.AuthenticationException: Authentication failed
        paramiko.SSHException: SSH connection failed
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if key_file:
            client.connect(host, port=port, username=username, key_filename=key_file,
                          timeout=timeout, look_for_keys=False)
            logging.info(f"Connected to {host} using key authentication")
        else:
            client.connect(host, port=port, username=username, password=password,
                          timeout=timeout, allow_agent=False, look_for_keys=False)
            logging.info(f"Connected to {host} using password authentication")
        return client
    except paramiko.AuthenticationException as e:
        logging.error(f"Authentication failed for {host}: {e}")
        raise
    except paramiko.SSHException as e:
        logging.error(f"SSH connection failed to {host}: {e}")
        raise


def execute_command(client: paramiko.SSHClient, command: str) -> str:
    """Execute command on remote device and return output."""
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=10)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        
        if error and 'Invalid command' in error:
            logging.warning(f"Command not supported: {command}")
            return ""
        
        return output
    except paramiko.SSHException as e:
        logging.error(f"Failed to execute command: {e}")
        return ""


def parse_ios_health(cpu_output: str, mem_output: str) -> Dict[str, str]:
    """Parse health metrics from Cisco IOS output."""
    health = {"cpu": "N/A", "memory": "N/A"}
    
    for line in cpu_output.split('\n'):
        if 'CPU utilization' in line and 'one minute' in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if part == 'minute':
                    health["cpu"] = parts[i + 1]
                    break
    
    for line in mem_output.split('\n'):
        if 'Processor' in line and '%' in line:
            parts = line.split()
            if len(parts) >= 2:
                health["memory"] = f"{parts[-2]}%"
                break
    
    return health


def parse_eos_health(output: str) -> Dict[str, str]:
    """Parse health metrics from Arista EOS output."""
    health = {"cpu": "N/A", "memory": "N/A"}
    
    for line in output.split('\n'):
        if 'CPU' in line and '%' in line:
            parts = line.split()
            for part in parts:
                if '%' in part:
                    health["cpu"] = part
                    break
        elif 'Memory' in line and '%' in line:
            parts = line.split()
            for part in parts:
                if '%' in part:
                    health["memory"] = part
                    break
    
    return health


def check_device_health(host: str, username: str, password: Optional[str] = None,
                        key_file: Optional[str] = None,
                        device_type: str = "auto") -> Dict[str, str]:
    """
    Check health metrics on network device.
    
    Args:
        host: Device IP or hostname
        username: SSH username
        password: SSH password
        key_file: SSH key file path
        device_type: Device type (ios, eos, auto)
        
    Returns:
        Dictionary containing health metrics
    """
    health = {"device": host, "status": "down", "cpu": "N/A", "memory": "N/A"}
    
    try:
        client = connect_device(host, username, password, key_file)
        
        if device_type == "auto":
            version = execute_command(client, "show version | include Arista")
            device_type = "eos" if version else "ios"
            logging.info(f"Detected device type: {device_type}")
        
        if device_type == "eos":
            show_cmd = "show system resources"
            output = execute_command(client, show_cmd)
            health.update(parse_eos_health(output))
        else:
            cpu_cmd = "show processes cpu | include CPU"
            mem_cmd = "show processes memory | include Processor"
            cpu_out = execute_command(client, cpu_cmd)
            mem_out = execute_command(client, mem_cmd)
            health.update(parse_ios_health(cpu_out, mem_out))
        
        health["status"] = "up"
        client.close()
        logging.info(f"Health check completed for {host}")
        
    except Exception as e:
        logging.error(f"Health check failed for {host}: {e}")
    
    return health


def main():
    parser = argparse.ArgumentParser(
        description="Check network device health metrics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--key", dest="key_file", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--device-type", default="auto",
                       choices=["ios", "eos", "auto"],
                       help="Device type (default: auto-detect)")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    
    if not args.password and not args.key_file:
        logging.error("Either --password or --key must be provided")
        sys.exit(1)
    
    health = check_device_health(
        host=args.host,
        username=args.username,
        password=args.password,
        key_file=args.key_file,
        device_type=args.device_type
    )
    
    print(f"\nDevice Health Report: {health['device']}")
    print(f"  Status:  {health['status']}")
    print(f"  CPU:     {health['cpu']}")
    print(f"  Memory:  {health['memory']}")
    
    if health['status'] == 'down':
        sys.exit(1)


if __name__ == "__main__":
    main()
```