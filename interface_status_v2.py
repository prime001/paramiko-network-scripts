```python
"""
OSPF Neighbor Status Checker

Retrieves and displays OSPF neighbor status from network devices for monitoring
routing adjacency health and troubleshooting neighbor state issues.

Usage:
    python ospf_neighbor_status.py -d 192.168.1.1 -u admin -p password
    python ospf_neighbor_status.py -d 192.168.1.1 -u admin -p password --filter-state FULL

Prerequisites:
    - paramiko (pip install paramiko)
    - Network device with SSH enabled
    - User credentials with appropriate privilege level
    - OSPF configured on the device
"""

import argparse
import logging
import sys
from paramiko import AutoAddPolicy, SSHClient
from paramiko.ssh_exception import (
    AuthenticationException,
    NoValidConnectionsError,
    SSHException,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def connect_device(host, username, password, timeout=10):
    """Establish SSH connection to network device."""
    try:
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(
            host,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False
        )
        logger.info(f"Connected to {host}")
        return client
    except AuthenticationException:
        logger.error(f"Authentication failed for {host}")
        sys.exit(1)
    except (NoValidConnectionsError, SSHException) as e:
        logger.error(f"Connection error to {host}: {e}")
        sys.exit(1)


def get_ospf_neighbors(client):
    """Retrieve OSPF neighbor information from device."""
    try:
        stdin, stdout, stderr = client.exec_command(
            'show ip ospf neighbor',
            timeout=10
        )
        return stdout.read().decode('utf-8')
    except SSHException as e:
        logger.error(f"Error executing command: {e}")
        sys.exit(1)


def parse_ospf_output(output, filter_state=None):
    """Parse OSPF neighbor output into structured data."""
    neighbors = []
    for line in output.split('\n'):
        line = line.strip()
        if not line or 'Neighbor' in line or '---' in line:
            continue

        parts = line.split()
        if len(parts) >= 5:
            neighbor = {
                'neighbor_id': parts[0],
                'priority': parts[1],
                'state': parts[2],
                'dead_time': parts[3],
                'interface': parts[4]
            }
            if filter_state is None or neighbor['state'] == filter_state:
                neighbors.append(neighbor)

    return neighbors


def display_neighbors(neighbors):
    """Display OSPF neighbors in formatted table."""
    if not neighbors:
        print("No OSPF neighbors found.")
        return

    header = (
        f"{'Neighbor ID':<15} {'Priority':<10} "
        f"{'State':<12} {'Dead Time':<12} {'Interface':<15}"
    )
    print(header)
    print('-' * len(header))

    for nb in neighbors:
        print(
            f"{nb['neighbor_id']:<15} {nb['priority']:<10} "
            f"{nb['state']:<12} {nb['dead_time']:<12} "
            f"{nb['interface']:<15}"
        )

    print(f"\nTotal neighbors: {len(neighbors)}")
    state_counts = {}
    for nb in neighbors:
        state = nb['state']
        state_counts[state] = state_counts.get(state, 0) + 1

    for state, count in sorted(state_counts.items()):
        symbol = "✓" if state == "FULL" else "✗"
        print(f"  {symbol} {state}: {count}")


def main():
    parser = argparse.ArgumentParser(
        description='Check OSPF neighbor status on network devices'
    )
    parser.add_argument('-d', '--device', required=True,
                        help='Device IP or hostname')
    parser.add_argument('-u', '--username', required=True,
                        help='SSH username')
    parser.add_argument('-p', '--password', required=True,
                        help='SSH password')
    parser.add_argument('--filter-state',
                        help='Filter by neighbor state (e.g., FULL)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='SSH timeout in seconds')

    args = parser.parse_args()

    logger.info(f"Checking OSPF neighbors on {args.device}")

    client = connect_device(args.device, args.username, args.password,
                           args.timeout)
    try:
        output = get_ospf_neighbors(client)
        neighbors = parse_ospf_output(output, args.filter_state)
        display_neighbors(neighbors)
    finally:
        client.close()
        logger.info("Disconnected")


if __name__ == '__main__':
    main()
```