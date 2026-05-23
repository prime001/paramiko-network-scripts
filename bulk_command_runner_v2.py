```python
"""
Device Uptime and System Health Reporter.

Connects to network devices via SSH, collects system information (uptime, memory,
CPU load), and generates a health status report. Useful for capacity planning and
identifying unhealthy devices.

Usage:
    python device_health_reporter.py --hosts 10.0.0.1 10.0.0.2 \
        --username admin --password secret --output report.csv

Prerequisites:
    - paramiko: pip install paramiko
    - Network devices must have SSH enabled
    - User credentials must have sufficient privileges to run 'show version'
"""

import argparse
import csv
import json
import logging
import sys
from datetime import datetime
from typing import Dict, List, Optional

import paramiko


def setup_logging(verbose: bool = False) -> None:
    """Configure logging output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def connect_device(host: str, username: str, password: str,
                   port: int = 22, timeout: int = 10) -> Optional[paramiko.SSHClient]:
    """Establish SSH connection to device."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password,
                      port=port, timeout=timeout, look_for_keys=False)
        logging.debug(f"Connected to {host}")
        return client
    except paramiko.AuthenticationException:
        logging.error(f"Authentication failed for {host}")
        return None
    except paramiko.SSHException as e:
        logging.error(f"SSH error on {host}: {e}")
        return None
    except Exception as e:
        logging.error(f"Connection error to {host}: {e}")
        return None


def get_device_info(client: paramiko.SSHClient, host: str) -> Dict:
    """Collect uptime and system health data from device."""
    info = {'host': host, 'status': 'unreachable'}

    try:
        stdin, stdout, stderr = client.exec_command('show version')
        output = stdout.read().decode()
        
        info['status'] = 'reachable'
        
        if 'uptime' in output.lower():
            for line in output.split('\n'):
                if 'uptime' in line.lower():
                    info['uptime'] = line.strip()
                    break
        
        if 'version' in output.lower():
            for line in output.split('\n'):
                if 'version' in line.lower() and 'Cisco' in output:
                    info['version'] = line.strip()
                    break
        
        stdin, stdout, stderr = client.exec_command('show processes cpu | include CPU')
        output = stdout.read().decode().strip()
        if output:
            info['cpu_load'] = output
        
        stdin, stdout, stderr = client.exec_command('show memory | include Processor')
        output = stdout.read().decode().strip()
        if output:
            info['memory'] = output
        
        logging.info(f"Collected health data from {host}")
        
    except Exception as e:
        logging.warning(f"Error collecting data from {host}: {e}")
        info['status'] = 'error'
        info['error'] = str(e)
    
    return info


def report_health(devices: List[Dict], output_file: Optional[str] = None,
                  format_type: str = 'csv') -> None:
    """Generate and output health report."""
    if format_type == 'json':
        output = json.dumps(devices, indent=2)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
        else:
            print(output)
    
    elif format_type == 'csv':
        if not devices:
            logging.warning("No device data to report")
            return
        
        fieldnames = ['host', 'status', 'uptime', 'version', 'cpu_load', 'memory', 'error']
        
        if output_file:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, restval='')
                writer.writeheader()
                writer.writerows(devices)
            logging.info(f"Report written to {output_file}")
        else:
            print('\n'.join(fieldnames))
            for device in devices:
                values = [str(device.get(f, '')) for f in fieldnames]
                print(','.join(values))
    
    else:
        for device in devices:
            print(f"\n--- {device['host']} ---")
            for key, value in device.items():
                if key != 'host':
                    print(f"{key}: {value}")


def main():
    """Main execution."""
    parser = argparse.ArgumentParser(
        description='Collect and report device health metrics'
    )
    parser.add_argument('--hosts', nargs='+', required=True,
                       help='Target device IP addresses')
    parser.add_argument('--username', '-u', required=True,
                       help='SSH username')
    parser.add_argument('--password', '-p', required=True,
                       help='SSH password')
    parser.add_argument('--port', type=int, default=22,
                       help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--output', '-o',
                       help='Output file for report')
    parser.add_argument('--format', choices=['csv', 'json'], default='csv',
                       help='Report format (default: csv)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    
    logging.info(f"Starting health check for {len(args.hosts)} device(s)")
    
    health_data = []
    
    for host in args.hosts:
        client = connect_device(host, args.username, args.password,
                               args.port, args.timeout)
        
        if client:
            device_info = get_device_info(client, host)
            health_data.append(device_info)
            client.close()
        else:
            health_data.append({
                'host': host,
                'status': 'connection_failed',
                'error': 'Unable to establish SSH connection'
            })
    
    report_health(health_data, args.output, args.format)
    
    reachable = sum(1 for d in health_data if d['status'] == 'reachable')
    logging.info(f"Health check complete: {reachable}/{len(args.hosts)} reachable")


if __name__ == '__main__':
    main()
```