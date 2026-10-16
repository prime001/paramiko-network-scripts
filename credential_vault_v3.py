#!/usr/bin/env python3
"""
Device Performance Health Monitor

Collects CPU, memory, and uptime metrics from network devices via SSH.
Stores metrics with timestamps for trend analysis and alerting on thresholds.

Prerequisites:
- paramiko library installed
- SSH access to network devices
- Devices support 'show processes cpu' and 'show memory' commands

Usage:
    python device_health_monitor.py --device 192.168.1.1 \
        --username admin --password secret --output metrics.csv

    python device_health_monitor.py --device-file devices.txt \
        --username admin --password secret --cpu-threshold 80
"""

import argparse
import csv
import logging
import sys
from datetime import datetime

import paramiko
from paramiko.ssh_exception import SSHException, AuthException


def setup_logging(log_file=None):
    """Configure logging with optional file output."""
    log_format = '%(asctime)s [%(levelname)s] %(message)s'
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=logging.INFO, format=log_format, handlers=handlers)


def connect_to_device(host, username, password, timeout=10):
    """Establish SSH connection to network device."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password,
                      timeout=timeout, look_for_keys=False)
        logging.info(f"Connected to {host}")
        return client
    except AuthException:
        logging.error(f"Authentication failed for {host}")
        return None
    except SSHException as e:
        logging.error(f"SSH connection error to {host}: {e}")
        return None
    except Exception as e:
        logging.error(f"Failed to connect to {host}: {e}")
        return None


def collect_device_metrics(client, device_ip):
    """Collect CPU, memory, and uptime from device."""
    metrics = {
        'timestamp': datetime.now().isoformat(),
        'device': device_ip,
        'cpu_percent': None,
        'memory_percent': None,
        'uptime': None,
        'status': 'error'
    }

    try:
        # Get CPU utilization
        stdin, stdout, stderr = client.exec_command('show processes cpu | inc CPU')
        cpu_output = stdout.read().decode('utf-8').strip()
        if cpu_output:
            try:
                parts = cpu_output.split()
                cpu_val = next(p for p in parts if '%' in p).rstrip('%')
                metrics['cpu_percent'] = float(cpu_val)
            except (ValueError, StopIteration):
                pass

        # Get memory usage
        stdin, stdout, stderr = client.exec_command('show memory | inc Processor')
        mem_output = stdout.read().decode('utf-8').strip()
        if mem_output:
            try:
                parts = mem_output.split()
                mem_val = float(parts[1])
                metrics['memory_percent'] = mem_val
            except (ValueError, IndexError):
                pass

        # Get uptime
        stdin, stdout, stderr = client.exec_command('show version | inc uptime')
        uptime_output = stdout.read().decode('utf-8').strip()
        if uptime_output:
            metrics['uptime'] = uptime_output

        metrics['status'] = 'success'
        logging.info(f"{device_ip}: CPU={metrics['cpu_percent']}%, "
                    f"Memory={metrics['memory_percent']}%")
        return metrics

    except Exception as e:
        logging.error(f"Error collecting metrics from {device_ip}: {e}")
        return metrics


def save_metrics_to_csv(metrics_list, output_file):
    """Save collected metrics to CSV file."""
    if not metrics_list:
        logging.warning("No metrics to save")
        return False

    try:
        with open(output_file, 'a', newline='') as csvfile:
            fieldnames = ['timestamp', 'device', 'cpu_percent', 'memory_percent',
                         'uptime', 'status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header only if file is empty
            if csvfile.tell() == 0:
                writer.writeheader()

            for metric in metrics_list:
                writer.writerow(metric)

        logging.info(f"Saved {len(metrics_list)} metric(s) to {output_file}")
        return True

    except IOError as e:
        logging.error(f"Failed to write metrics: {e}")
        return False


def check_thresholds(metrics_list, cpu_threshold, mem_threshold):
    """Check metrics against thresholds and log alerts."""
    alerts = []
    for metric in metrics_list:
        if metric['status'] != 'success':
            continue

        if (metric['cpu_percent'] is not None and
                metric['cpu_percent'] > cpu_threshold):
            alerts.append(f"ALERT: {metric['device']} high CPU: "
                         f"{metric['cpu_percent']}% (threshold: {cpu_threshold}%)")

        if (metric['memory_percent'] is not None and
                metric['memory_percent'] > mem_threshold):
            alerts.append(f"ALERT: {metric['device']} high memory: "
                         f"{metric['memory_percent']}% (threshold: {mem_threshold}%)")

    for alert in alerts:
        logging.warning(alert)

    return alerts


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Monitor network device health metrics'
    )
    parser.add_argument('--device', help='Single device IP or hostname')
    parser.add_argument('--device-file', help='File with device list (one per line)')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--output', default='device_metrics.csv',
                       help='Output CSV file')
    parser.add_argument('--cpu-threshold', type=int, default=85,
                       help='CPU alert threshold percent (default: 85)')
    parser.add_argument('--memory-threshold', type=int, default=90,
                       help='Memory alert threshold percent (default: 90)')
    parser.add_argument('--log-file', help='Log file path')
    parser.add_argument('--timeout', type=int, default=10,
                       help='SSH connection timeout seconds')

    args = parser.parse_args()
    setup_logging(args.log_file)

    # Build device list
    devices = []
    if args.device:
        devices = [args.device]
    elif args.device_file:
        try:
            with open(args.device_file) as f:
                devices = [line.strip() for line in f if line.strip()]
        except IOError as e:
            logging.error(f"Cannot read device file: {e}")
            sys.exit(1)
    else:
        logging.error("Provide --device or --device-file")
        sys.exit(1)

    if not devices:
        logging.error("No devices to monitor")
        sys.exit(1)

    # Collect metrics
    all_metrics = []
    for device in devices:
        client = connect_to_device(device, args.username, args.password,
                                   args.timeout)
        if client:
            metrics = collect_device_metrics(client, device)
            all_metrics.append(metrics)
            client.close()

    # Process results
    if not all_metrics:
        logging.error("Failed to collect metrics from any device")
        sys.exit(1)

    save_metrics_to_csv(all_metrics, args.output)
    check_thresholds(all_metrics, args.cpu_threshold, args.memory_threshold)
    logging.info(f"Complete: processed {len(all_metrics)} device(s)")


if __name__ == '__main__':
    main()