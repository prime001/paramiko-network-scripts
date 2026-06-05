```python
#!/usr/bin/env python3
"""
Device Facts Collector

Collects system facts from network devices (hostname, model, OS version, serial number,
uptime, memory, interfaces) via SSH using Paramiko. Useful for device inventory, 
documentation, and change tracking.

Usage:
    python device_facts.py --device 192.168.1.1 --username admin --password pass
    python device_facts.py --device 192.168.1.1 --username admin --password pass --format json
    python device_facts.py --device-file devices.txt --username admin --password pass

Prerequisites:
    - paramiko: pip install paramiko
    - Network devices must have SSH enabled
    - SSH credentials with sufficient privileges to execute show commands
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import paramiko


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with appropriate level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def connect_device(host: str, username: str, password: str,
                  timeout: int = 10) -> paramiko.SSHClient:
    """Establish SSH connection to device."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, password=password,
                      timeout=timeout, look_for_keys=False,
                      allow_agent=False)
        return client
    except paramiko.AuthenticationException as e:
        raise ConnectionError(f"Authentication failed for {host}: {e}")
    except paramiko.SSHException as e:
        raise ConnectionError(f"SSH error connecting to {host}: {e}")
    except Exception as e:
        raise ConnectionError(f"Failed to connect to {host}: {e}")


def execute_command(client: paramiko.SSHClient, command: str) -> str:
    """Execute command and return output."""
    _, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    if error and "warning" not in error.lower():
        logging.debug(f"Command '{command}' stderr: {error}")
    return output


def extract_facts_ios(client: paramiko.SSHClient, host: str) -> dict:
    """Extract facts from Cisco IOS/IOS-XE device."""
    facts = {"host": host, "os": "ios", "facts": {}}
    
    try:
        version_output = execute_command(client, "show version")
        lines = version_output.split("\n")
        
        for line in lines:
            if "Cisco" in line and "Version" in line:
                parts = line.split("Version")
                if len(parts) > 1:
                    facts["facts"]["os_version"] = parts[1].strip()[:25]
            if "uptime is" in line:
                facts["facts"]["uptime"] = line.split("uptime is")[1].strip()
            if "System Serial Number" in line:
                facts["facts"]["serial_number"] = line.split(":")[-1].strip()
            if "Model Number" in line or "Model:" in line:
                facts["facts"]["model"] = line.split(":")[-1].strip()
        
        hostname_out = execute_command(client, "show running-config | include hostname")
        if hostname_out and "hostname" in hostname_out:
            hostname = hostname_out.split()[-1]
            facts["facts"]["hostname"] = hostname
        
        interfaces_out = execute_command(client, "show ip interface brief")
        interface_count = len([l for l in interfaces_out.split("\n")
                              if l.strip() and "Interface" not in l])
        facts["facts"]["interface_count"] = interface_count
        
    except Exception as e:
        logging.debug(f"Error extracting IOS facts from {host}: {e}")
    
    return facts


def extract_facts_generic(client: paramiko.SSHClient, host: str) -> dict:
    """Extract basic facts from generic device."""
    facts = {"host": host, "os": "unknown", "facts": {}}
    
    try:
        version_output = execute_command(client, "show version")
        facts["facts"]["version"] = version_output[:150]
    except Exception as e:
        logging.debug(f"Error extracting facts from {host}: {e}")
    
    return facts


def get_device_facts(host: str, username: str, password: str) -> dict:
    """Collect facts from a network device."""
    logger = logging.getLogger(__name__)
    logger.info(f"Collecting facts from {host}")
    
    try:
        client = connect_device(host, username, password)
        facts = extract_facts_ios(client, host)
        if not facts.get("facts"):
            facts = extract_facts_generic(client, host)
        client.close()
        logger.info(f"Successfully collected facts from {host}")
        return facts
    except Exception as e:
        logger.error(f"Failed to collect facts from {host}: {e}")
        return {"host": host, "error": str(e)}


def format_output(facts: dict, format_type: str = "table") -> str:
    """Format facts for output."""
    if format_type == "json":
        return json.dumps(facts, indent=2)
    
    if "error" in facts:
        return f"{facts['host']}: ERROR - {facts['error']}"
    
    output = f"\nDevice: {facts['host']} ({facts.get('os', 'unknown')})\n"
    output += "-" * 50 + "\n"
    for key, value in facts.get("facts", {}).items():
        label = key.replace("_", " ").title()
        output += f"  {label}: {value}\n"
    return output


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Collect system facts from network devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s --device 192.168.1.1 -u admin -p password\n"
               "  %(prog)s --device-file devices.txt -u admin -p password --format json"
    )
    
    parser.add_argument("--device", help="Target device IP or hostname")
    parser.add_argument("--device-file", help="File with device IPs (one per line)")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                       help="Output format (default: table)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--timeout", type=int, default=10,
                       help="SSH connection timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    if not args.device and not args.device_file:
        parser.error("Either --device or --device-file must be specified")
    
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    devices = []
    if args.device:
        devices = [args.device]
    elif args.device_file:
        try:
            device_file = Path(args.device_file)
            devices = device_file.read_text().strip().split("\n")
            devices = [d.strip() for d in devices if d.strip()]
        except FileNotFoundError:
            logger.error(f"Device file not found: {args.device_file}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error reading device file: {e}")
            sys.exit(1)
    
    results = []
    for device in devices:
        facts = get_device_facts(device, args.username, args.password)
        results.append(facts)
    
    output_text = ""
    for facts in results:
        output_text += format_output(facts, args.format) + "\n"
    
    if args.output:
        try:
            Path(args.output).write_text(output_text)
            logger.info(f"Output saved to {args.output}")
        except Exception as e:
            logger.error(f"Failed to write output file: {e}")
            sys.exit(1)
    else:
        print(output_text)


if __name__ == "__main__":
    main()
```