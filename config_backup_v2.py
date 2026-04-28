```python
#!/usr/bin/env python3
"""
System Log Analyzer for Network Devices

Connects to network devices via SSH, retrieves system logs, analyzes them for
critical events, and generates a detailed report. Useful for identifying device
issues, configuration changes, and security events in a network environment.

Usage:
    python system_log_analyzer.py --host 192.168.1.1 --username admin --device-type cisco
    python system_log_analyzer.py --host 10.0.0.5 --username netadmin --password secret

Prerequisites:
    - paramiko library (pip install paramiko)
    - SSH access to network devices with appropriate credentials
    - Devices must support log retrieval commands (show log / show system log)
"""

import argparse
import logging
import paramiko
import sys
from datetime import datetime


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkLogAnalyzer:
    """Analyzes system logs from network devices for critical events."""
    
    DEVICE_COMMANDS = {
        'cisco': 'show log',
        'arista': 'show log',
        'juniper': 'show system log',
        'generic': 'show system log'
    }
    
    CRITICAL_KEYWORDS = [
        'CRITICAL', 'FATAL', 'ERROR', 'FAILED', 'DOWN',
        'RESTART', 'RELOAD', 'PANIC', 'CRASH', 'OVERLOAD'
    ]
    
    def __init__(self, host, username, password, device_type='cisco', timeout=30):
        """Initialize analyzer with connection parameters."""
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.timeout = timeout
        self.client = None
        self.logs = []
        self.critical_events = []
    
    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"Successfully connected to {self.host}")
            return True
        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed for {self.host}: {e}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH connection failed to {self.host}: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def retrieve_logs(self):
        """Retrieve system logs from device via SSH."""
        if not self.client:
            logger.error("Not connected to device")
            return False
        
        try:
            command = self.DEVICE_COMMANDS.get(
                self.device_type,
                self.DEVICE_COMMANDS['generic']
            )
            logger.info(f"Executing command: {command}")
            
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=self.timeout
            )
            output = stdout.read().decode('utf-8', errors='ignore')
            error_output = stderr.read().decode('utf-8', errors='ignore')
            
            if error_output and not output:
                logger.warning(f"Command error: {error_output[:100]}")
                return False
            
            self.logs = [line for line in output.split('\n') if line.strip()]
            logger.info(f"Retrieved {len(self.logs)} log lines from {self.host}")
            return True
        
        except paramiko.SSHException as e:
            logger.error(f"SSH error during log retrieval: {e}")
            return False
        except Exception as e:
            logger.error(f"Error retrieving logs: {e}")
            return False
    
    def analyze_logs(self):
        """Identify and catalog critical events in logs."""
        if not self.logs:
            logger.warning("No logs available for analysis")
            return
        
        for idx, line in enumerate(self.logs):
            for keyword in self.CRITICAL_KEYWORDS:
                if keyword.lower() in line.lower():
                    self.critical_events.append({
                        'line_number': idx,
                        'keyword': keyword,
                        'message': line.strip()
                    })
                    break
        
        logger.info(f"Analysis complete: found {len(self.critical_events)} critical events")
    
    def save_report(self, output_file=None):
        """Generate and save analysis report to file."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"log_analysis_{self.host}_{timestamp}.txt"
        
        try:
            with open(output_file, 'w') as f:
                f.write("=" * 70 + "\n")
                f.write("NETWORK DEVICE LOG ANALYSIS REPORT\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"Device:           {self.host}\n")
                f.write(f"Device Type:      {self.device_type}\n")
                f.write(f"Analysis Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Log Lines:  {len(self.logs)}\n")
                f.write(f"Critical Events:  {len(self.critical_events)}\n\n")
                
                f.write("=" * 70 + "\n")
                f.write("CRITICAL EVENTS DETECTED\n")
                f.write("=" * 70 + "\n\n")
                
                if self.critical_events:
                    for event in self.critical_events:
                        f.write(f"[{event['keyword']}] {event['message']}\n")
                else:
                    f.write("No critical events found - device appears healthy.\n")
                
                f.write("\n" + "=" * 70 + "\n")
                f.write("RECENT LOG ENTRIES (Last 25 lines)\n")
                f.write("=" * 70 + "\n\n")
                f.write('\n'.join(self.logs[-25:]))
            
            logger.info(f"Report saved to {output_file}")
            return output_file
        
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return None
    
    def disconnect(self):
        """Close SSH connection gracefully."""
        if self.client:
            self.client.close()
            logger.info("Disconnected from device")


def main():
    """Main entry point for log analyzer."""
    parser = argparse.ArgumentParser(
        description='Analyze system logs from network devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  python system_log_analyzer.py --host 192.168.1.1 --username admin\n'
               '  python system_log_analyzer.py --host 10.0.0.5 --username admin '
               '--password secret --device-type cisco\n'
    )
    
    parser.add_argument('--host', required=True, help='Target device IP or hostname')
    parser.add_argument('--username', required=True, help='SSH username for authentication')
    parser.add_argument('--password', help='SSH password (will prompt if not provided)')
    parser.add_argument(
        '--device-type',
        default='cisco',
        choices=['cisco', 'arista', 'juniper', 'generic'],
        help='Device OS type for command selection'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='SSH connection timeout in seconds'
    )
    parser.add_argument('--output', help='Custom output filename for report')
    
    args = parser.parse_args()
    
    password = args.password
    if not password:
        import getpass
        password = getpass.getpass(f"Enter SSH password for {args.username}: ")
    
    analyzer = NetworkLogAnalyzer(
        host=args.host,
        username=args.username,
        password=password,
        device_type=args.device_type,
        timeout=args.timeout
    )
    
    try:
        if not analyzer.connect():
            logger.error("Failed to establish connection")
            sys.exit(1)
        
        if not analyzer.retrieve_logs():
            logger.error("Failed to retrieve logs")
            sys.exit(1)
        
        analyzer.analyze_logs()
        report_file = analyzer.save_report(args.output)
        
        print("\n" + "=" * 60)
        print(f"Analysis Complete - {analyzer.host}")
        print("=" * 60)
        print(f"Total Log Lines:    {len(analyzer.logs)}")
        print(f"Critical Events:    {len(analyzer.critical_events)}")
        if report_file:
            print(f"Report Location:    {report_file}")
        
        if analyzer.critical_events:
            print(f"\n⚠️  Critical Events Found:")
            for event in analyzer.critical_events[:5]:
                print(f"  [{event['keyword']}] {event['message'][:65]}")
            if len(analyzer.critical_events) > 5:
                print(f"  ... and {len(analyzer.critical_events) - 5} more")
        else:
            print("\n✓ No critical events detected")
        print()
    
    finally:
        analyzer.disconnect()


if __name__ == '__main__':
    main()
```