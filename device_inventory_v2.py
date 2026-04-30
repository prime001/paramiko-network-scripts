```python
"""
System Health Monitor for Network Devices

Connects to network devices via SSH and collects system health metrics
(CPU, memory, uptime) with configurable threshold alerting.

Prerequisites:
    - paramiko library installed
    - SSH access to target devices with credentials
    - Devices support 'show version', 'show processes cpu', 'show memory' commands
    - SSH credentials via password or key file

Usage:
    python system_health_monitor.py -d 192.168.1.1 -u admin -p password
    python system_health_monitor.py -f inventory.txt -u admin -p password
    python system_health_monitor.py -d 10.0.0.5 -u admin -c ~/.ssh/id_rsa --ssh-key
"""

import paramiko
import argparse
import logging
import sys
import re
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def connect_device(host, username, password=None, key_file=None, port=22, timeout=10):
    """Establish SSH connection to network device."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if key_file:
            client.connect(host, port=port, username=username, key_filename=key_file, timeout=timeout)
            logger.info(f"Connected to {host} with key-based auth")
        else:
            client.connect(host, port=port, username=username, password=password, timeout=timeout)
            logger.info(f"Connected to {host}")
        return client
    except paramiko.AuthenticationException as e:
        logger.error(f"Authentication failed for {host}: {e}")
        raise
    except Exception as e:
        logger.error(f"Connection error to {host}: {e}")
        raise


def execute_command(client, command):
    """Execute command and return output as string."""
    try:
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode('utf-8')
    except Exception as e:
        logger.warning(f"Command failed '{command}': {e}")
        return ""


def parse_uptime(version_output):
    """Extract device uptime from version output."""
    match = re.search(r'uptime is (.+?)(?:\n|$)', version_output, re.IGNORECASE)
    return match.group(1).strip() if match else None


def parse_hostname(version_output):
    """Extract device hostname from version output."""
    match = re.search(r'(?:hostname|device id)[:\s]+(\S+)', version_output, re.IGNORECASE)
    return match.group(1) if match else None


def parse_cpu(cpu_output):
    """Extract CPU utilization percentage from process output."""
    match = re.search(r'(?:CPU utilization for five seconds|5 second).*?:\s*(\d+)%', 
                     cpu_output, re.IGNORECASE | re.DOTALL)
    return int(match.group(1)) if match else None


def parse_memory(memory_output):
    """Extract memory utilization percentage from memory output."""
    match = re.search(r'Total:\s*(\d+)K.*?Free:\s*(\d+)K', memory_output, re.IGNORECASE | re.DOTALL)
    if match:
        try:
            total = int(match.group(1))
            free = int(match.group(2))
            return round(100 * (total - free) / total, 2) if total > 0 else None
        except (IndexError, ValueError):
            pass
    return None


def get_health_metrics(client, host):
    """Collect system health metrics from device."""
    metrics = {'host': host, 'hostname': host, 'cpu': None, 'memory': None, 'uptime': None}
    
    try:
        version = execute_command(client, 'show version')
        cpu = execute_command(client, 'show processes cpu')
        memory = execute_command(client, 'show memory')
        
        metrics['hostname'] = parse_hostname(version) or host
        metrics['uptime'] = parse_uptime(version)
        metrics['cpu'] = parse_cpu(cpu)
        metrics['memory'] = parse_memory(memory)
        
        logger.info(f"{host}: CPU={metrics['cpu']}% Memory={metrics['memory']}%")
        return metrics
        
    except Exception as e:
        logger.error(f"Error collecting metrics from {host}: {e}")
        return metrics


def check_thresholds(metrics, cpu_threshold, mem_threshold):
    """Return list of threshold violation alerts."""
    alerts = []
    if metrics['cpu'] and metrics['cpu'] > cpu_threshold:
        alerts.append(f"  ⚠ CPU: {metrics['cpu']}% exceeds {cpu_threshold}% threshold")
    if metrics['memory'] and metrics['memory'] > mem_threshold:
        alerts.append(f"  ⚠ Memory: {metrics['memory']}% exceeds {mem_threshold}% threshold")
    return alerts


def print_report(results):
    """Print health report to console."""
    print(f"\n{'='*70}")
    print(f"System Health Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")
    
    for metrics, alerts in results:
        print(f"Device: {metrics['hostname']}")
        print(f"  Address: {metrics['host']}")
        print(f"  Uptime: {metrics['uptime'] or 'N/A'}")
        print(f"  CPU: {metrics['cpu']}%" if metrics['cpu'] is not None else "  CPU: N/A")
        print(f"  Memory: {metrics['memory']}%" if metrics['memory'] is not None else "  Memory: N/A")
        for alert in alerts:
            print(alert)
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Monitor system health on network devices',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-d', '--device', help='Single device IP/hostname')
    parser.add_argument('-f', '--file', help='Inventory file (one IP per line)')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password')
    parser.add_argument('-c', '--key-file', help='SSH private key file')
    parser.add_argument('--ssh-key', action='store_true', help='Use key-based authentication')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--cpu-threshold', type=int, default=80, help='CPU alert threshold %% (default: 80)')
    parser.add_argument('--memory-threshold', type=int, default=85, help='Memory alert threshold %% (default: 85)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout seconds')
    
    args = parser.parse_args()
    
    devices = []
    if args.device:
        devices = [args.device]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                devices = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.error(f"File not found: {args.file}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
    
    password = args.password if not args.ssh_key else None
    key_file = args.key_file if args.ssh_key else None
    
    if not args.ssh_key and not args.password:
        logger.error("Provide --password or use --ssh-key with --key-file")
        sys.exit(1)
    
    results = []
    for device in devices:
        try:
            client = connect_device(device, args.username, password, key_file, args.port, args.timeout)
            metrics = get_health_metrics(client, device)
            alerts = check_thresholds(metrics, args.cpu_threshold, args.memory_threshold)
            results.append((metrics, alerts))
            client.close()
        except Exception:
            results.append(({'host': device, 'hostname': device}, ["Connection failed"]))
    
    print_report(results)
    
    failed = sum(1 for m, a in results if "Connection failed" in a)
    sys.exit(1 if failed > 0 else 0)


if __name__ == '__main__':
    main()
```