```python
"""
BGP Neighbor Status Monitor
============================

Monitor BGP neighbor adjacency status, uptime, and prefix counts.

Connects to network devices via SSH and retrieves BGP session information.
Supports Cisco IOS, IOS-XE platforms.

Usage:
    python bgp_neighbor_monitor.py --device 192.168.1.1 --user admin --password secret
    python bgp_neighbor_monitor.py -d router.example.com -u admin -p secret --asn 65000
    python bgp_neighbor_monitor.py --device 10.0.0.1 --vault creds.json --output json

Prerequisites:
    - paramiko (pip install paramiko)
    - Network device with SSH access and BGP enabled
    - Credentials with administrative access
    - Python 3.6+
"""

import argparse
import json
import logging
import sys
from typing import Dict, List, Optional

import paramiko


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BGPNeighborMonitor:
    """Monitor BGP neighbor status and metrics."""

    def __init__(self, host: str, username: str, password: str, asn: Optional[int] = None):
        self.host = host
        self.username = username
        self.password = password
        self.asn = asn
        self.client = None
        self.neighbors = []

    def connect(self) -> bool:
        """Establish SSH connection to device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Connected to {self.host}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException) as e:
            logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self.client:
            self.client.close()

    def execute_command(self, command: str) -> str:
        """Execute command and return output."""
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=10)
            return stdout.read().decode('utf-8')
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return ""

    def parse_bgp_summary(self, output: str) -> List[Dict]:
        """Parse BGP summary output."""
        neighbors = []
        lines = output.split('\n')
        skip_headers = True

        for line in lines:
            line = line.strip()
            if not line or skip_headers:
                if 'Neighbor' in line:
                    skip_headers = False
                continue

            parts = line.split()
            if len(parts) >= 6 and self._is_ip(parts[0]):
                try:
                    neighbor = {
                        'address': parts[0],
                        'version': parts[1],
                        'asn': parts[2],
                        'msg_received': int(parts[3]),
                        'msg_sent': int(parts[4]),
                        'table_version': parts[5] if len(parts) > 5 else 'N/A',
                        'in_queue': parts[6] if len(parts) > 6 else '0',
                        'out_queue': parts[7] if len(parts) > 7 else '0',
                        'status': parts[-1]
                    }
                    neighbors.append(neighbor)
                except (ValueError, IndexError):
                    continue

        return neighbors

    def _is_ip(self, s: str) -> bool:
        """Check if string is an IP address."""
        parts = s.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def get_bgp_summary(self) -> List[Dict]:
        """Retrieve BGP neighbor summary."""
        logger.info("Fetching BGP neighbor summary")
        cmd = "show ip bgp summary" if not self.asn else f"show ip bgp vrf * summary"
        output = self.execute_command(cmd)

        if not output:
            logger.warning("No BGP output received")
            return []

        self.neighbors = self.parse_bgp_summary(output)
        return self.neighbors

    def get_neighbor_detail(self, neighbor_ip: str) -> Dict:
        """Get detailed info for specific neighbor."""
        cmd = f"show ip bgp neighbor {neighbor_ip}"
        output = self.execute_command(cmd)

        detail = {'address': neighbor_ip}
        for line in output.split('\n'):
            line = line.strip()
            if 'BGP version' in line:
                detail['bgp_version'] = line.split(':')[1].strip() if ':' in line else 'N/A'
            elif 'Remote AS' in line:
                detail['remote_asn'] = line.split(':')[1].strip() if ':' in line else 'N/A'
            elif 'BGP state' in line:
                detail['state'] = line.split('=')[1].strip() if '=' in line else 'N/A'
            elif 'Up for' in line:
                detail['uptime'] = line.split('Up for')[1].strip() if 'Up for' in line else 'N/A'

        return detail

    def collect_data(self) -> List[Dict]:
        """Collect all BGP neighbor data."""
        if not self.connect():
            return []

        neighbors = self.get_bgp_summary()
        self.disconnect()
        return neighbors

    def display_summary(self) -> None:
        """Display BGP neighbor summary table."""
        if not self.neighbors:
            print("No BGP neighbors found")
            return

        print(f"\n{'Device':<20} {'Neighbor':<18} {'ASN':<8} {'State':<12}")
        print("-" * 60)
        for n in self.neighbors:
            state = n.get('status', 'unknown')
            print(f"{self.host:<20} {n['address']:<18} {n['asn']:<8} {state:<12}")
        print()


def load_credentials(vault_file: str) -> Dict:
    """Load credentials from JSON file."""
    try:
        with open(vault_file) as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Vault file not found: {vault_file}")
        return {}
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in vault: {vault_file}")
        return {}


def main():
    parser = argparse.ArgumentParser(
        description='Monitor BGP neighbor status on network devices'
    )
    parser.add_argument('-d', '--device', required=True, help='Device IP or hostname')
    parser.add_argument('-u', '--user', help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password')
    parser.add_argument('--vault', help='JSON credentials vault file')
    parser.add_argument('--asn', type=int, help='Local BGP ASN (optional)')
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    username = args.user
    password = args.password

    if args.vault:
        creds = load_credentials(args.vault)
        if args.device in creds:
            username = creds[args.device].get('username')
            password = creds[args.device].get('password')

    if not username or not password:
        logger.error("Username and password required")
        sys.exit(1)

    monitor = BGPNeighborMonitor(args.device, username, password, args.asn)
    neighbors = monitor.collect_data()

    if args.json:
        print(json.dumps(neighbors, indent=2))
    else:
        monitor.neighbors = neighbors
        monitor.display_summary()

    sys.exit(0 if neighbors else 1)


if __name__ == "__main__":
    main()
```