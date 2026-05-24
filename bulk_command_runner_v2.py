```python
#!/usr/bin/env python3
"""
Device Reachability Tester - Tests SSH connectivity to network devices.

Tests SSH reachability to devices in inventory and generates a connectivity report.
Useful for health checks and identifying unreachable or slow devices.

Usage:
    python device_reachability_tester.py -c credentials.json -i devices.json -o report.txt
    python device_reachability_tester.py -c creds.json -i devices.json --timeout 10

Prerequisites:
    - paramiko library: pip install paramiko
    - Credentials file (JSON format) with SSH credentials
    - Device inventory file (JSON or text format)
"""

import json
import argparse
import logging
import sys
import time
import paramiko

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_credentials(cred_file):
    """Load SSH credentials from JSON file."""
    try:
        with open(cred_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Credentials file not found: {cred_file}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in credentials file: {cred_file}")
        sys.exit(1)


def load_devices(device_file):
    """Load device list from JSON or text file."""
    try:
        with open(device_file, 'r') as f:
            content = f.read()
            if device_file.endswith('.json'):
                return json.loads(content)
            return [line.strip() for line in content.split('\n') if line.strip()]
    except FileNotFoundError:
        logger.error(f"Device file not found: {device_file}")
        sys.exit(1)


def test_device_reachability(host, username, password, timeout=5, port=22):
    """Test SSH reachability to a single device."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    start_time = time.time()
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False
        )
        response_time = time.time() - start_time
        return True, response_time, None
    except paramiko.AuthenticationException as e:
        return False, None, f"Authentication failed: {str(e)}"
    except paramiko.SSHException as e:
        return False, None, f"SSH error: {str(e)}"
    except Exception as e:
        return False, None, f"Connection failed: {str(e)}"
    finally:
        try:
            client.close()
        except Exception:
            pass


def run_reachability_test(devices, credentials, timeout=5, port=22):
    """Test reachability for all devices."""
    results = []
    username = credentials.get('username')
    password = credentials.get('password')

    if not username or not password:
        logger.error("Username or password not found in credentials")
        sys.exit(1)

    logger.info(f"Testing reachability for {len(devices)} device(s)...")

    for device in devices:
        host = device if isinstance(device, str) else device.get('host')
        dev_port = device.get('port', port) if isinstance(device, dict) else port

        logger.info(f"Testing {host}...")
        reachable, response_time, error = test_device_reachability(
            host, username, password, timeout, dev_port
        )

        results.append({
            'host': host,
            'port': dev_port,
            'reachable': reachable,
            'response_time': response_time,
            'error': error
        })

    return results


def generate_report(results):
    """Generate a formatted reachability report."""
    reachable_count = sum(1 for r in results if r['reachable'])
    unreachable_count = len(results) - reachable_count

    report_lines = [
        "=" * 70,
        "Device Reachability Report",
        "=" * 70,
        f"Total Devices: {len(results)}",
        f"Reachable: {reachable_count}",
        f"Unreachable: {unreachable_count}",
        "=" * 70,
        ""
    ]

    for result in results:
        status = "✓ REACHABLE" if result['reachable'] else "✗ UNREACHABLE"
        host_info = f"{result['host']}:{result['port']}"

        if result['reachable']:
            response = f" ({result['response_time']:.2f}s)"
            report_lines.append(f"{status:20} {host_info:30} {response}")
        else:
            report_lines.append(f"{status:20} {host_info:30}")
            if result['error']:
                report_lines.append(f"  └─ {result['error']}")

        report_lines.append("")

    return "\n".join(report_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Test SSH reachability to network devices"
    )
    parser.add_argument(
        '-c', '--credentials',
        required=True,
        help='Path to credentials JSON file'
    )
    parser.add_argument(
        '-i', '--inventory',
        required=True,
        help='Path to device inventory file (JSON or text)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Path to save report (optional)'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=5,
        help='SSH connection timeout in seconds (default: 5)'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=22,
        help='SSH port (default: 22)'
    )

    args = parser.parse_args()

    credentials = load_credentials(args.credentials)
    devices = load_devices(args.inventory)

    results = run_reachability_test(devices, credentials, args.timeout, args.port)
    report = generate_report(results)

    print(report)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to {args.output}")
        except IOError as e:
            logger.error(f"Failed to write report: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
```