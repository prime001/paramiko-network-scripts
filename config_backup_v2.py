```python
#!/usr/bin/env python3
"""
Device System Health Monitor

Monitors network device system resources (CPU, memory, disk) via SSH.
Retrieves health metrics, compares against thresholds, and reports
issues. Useful for capacity planning and proactive alerting.

Usage:
    python device_health_monitor.py --device 10.0.0.1 --user admin --port 22
    python device_health_monitor.py --device 10.0.0.1 --user admin --warn-cpu 75 --crit-cpu 90

Prerequisites:
    - paramiko library
    - SSH access to target device
    - Device must support standard show commands (IOS/IOS-XE/NX-OS)
"""

import argparse
import logging
import sys
from datetime import datetime
import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    SSHException,
    NoValidConnectionsError,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class DeviceHealthMonitor:
    def __init__(self, device, username, password, port=22):
        self.device = device
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.metrics = {}
        self.alerts = []

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                self.device,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            logger.info(f"Connected to {self.device}")
        except AuthenticationException:
            logger.error("Authentication failed")
            raise
        except (SSHException, NoValidConnectionsError) as e:
            logger.error(f"SSH connection failed: {e}")
            raise

    def execute_command(self, command):
        if not self.client:
            raise RuntimeError("Not connected")
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=10)
            output = stdout.read().decode("utf-8", errors="ignore")
            return output
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise

    def get_cpu_usage(self):
        output = self.execute_command("show processes cpu")
        for line in output.split("\n"):
            if "CPU utilization" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "utilization":
                        try:
                            cpu = float(parts[i + 1].rstrip("%"))
                            self.metrics["cpu"] = cpu
                            logger.info(f"CPU Usage: {cpu}%")
                            return cpu
                        except (ValueError, IndexError):
                            continue
        logger.warning("Could not parse CPU metrics")
        return None

    def get_memory_usage(self):
        output = self.execute_command("show memory statistics")
        for line in output.split("\n"):
            if "Processor" in line and "used" in line:
                parts = line.split()
                try:
                    total = int(parts[-4])
                    used = int(parts[-6])
                    if total > 0:
                        mem_pct = (used / total) * 100
                        self.metrics["memory"] = mem_pct
                        logger.info(f"Memory Usage: {mem_pct:.1f}%")
                        return mem_pct
                except (ValueError, IndexError):
                    continue
        logger.warning("Could not parse memory metrics")
        return None

    def get_disk_usage(self):
        output = self.execute_command("dir")
        total = None
        used = None
        for line in output.split("\n"):
            if "bytes total" in line:
                try:
                    parts = line.split()
                    total = int(parts[0])
                except (ValueError, IndexError):
                    continue
            if "bytes used" in line:
                try:
                    parts = line.split()
                    used = int(parts[0])
                except (ValueError, IndexError):
                    continue
        if total and used:
            disk_pct = (used / total) * 100
            self.metrics["disk"] = disk_pct
            logger.info(f"Disk Usage: {disk_pct:.1f}%")
            return disk_pct
        logger.warning("Could not parse disk metrics")
        return None

    def check_thresholds(self, warn_cpu=80, crit_cpu=95, warn_mem=85,
                         crit_mem=95, warn_disk=90, crit_disk=98):
        self.alerts = []
        cpu = self.metrics.get("cpu")
        if cpu:
            if cpu >= crit_cpu:
                self.alerts.append(f"CRITICAL: CPU at {cpu}%")
            elif cpu >= warn_cpu:
                self.alerts.append(f"WARNING: CPU at {cpu}%")

        mem = self.metrics.get("memory")
        if mem:
            if mem >= crit_mem:
                self.alerts.append(f"CRITICAL: Memory at {mem:.1f}%")
            elif mem >= warn_mem:
                self.alerts.append(f"WARNING: Memory at {mem:.1f}%")

        disk = self.metrics.get("disk")
        if disk:
            if disk >= crit_disk:
                self.alerts.append(f"CRITICAL: Disk at {disk:.1f}%")
            elif disk >= warn_disk:
                self.alerts.append(f"WARNING: Disk at {disk:.1f}%")

    def report(self):
        print("\n" + "=" * 60)
        print(f"Device Health Report: {self.device}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print(f"CPU Usage:    {self.metrics.get('cpu', 'N/A')}%")
        print(f"Memory Usage: {self.metrics.get('memory', 'N/A')}%")
        print(f"Disk Usage:   {self.metrics.get('disk', 'N/A')}%")
        if self.alerts:
            print("\nAlerts:")
            for alert in self.alerts:
                print(f"  • {alert}")
        else:
            print("\nStatus: All metrics within thresholds")
        print("=" * 60 + "\n")

    def disconnect(self):
        if self.client:
            self.client.close()
            logger.info("Disconnected")

    def run(self, warn_cpu=80, crit_cpu=95, warn_mem=85, crit_mem=95,
            warn_disk=90, crit_disk=98):
        try:
            self.connect()
            self.get_cpu_usage()
            self.get_memory_usage()
            self.get_disk_usage()
            self.check_thresholds(warn_cpu, crit_cpu, warn_mem, crit_mem,
                                 warn_disk, crit_disk)
            self.report()
            return 0 if not self.alerts else 1
        except Exception as e:
            logger.error(f"Monitor failed: {e}")
            return 2
        finally:
            self.disconnect()


def main():
    parser = argparse.ArgumentParser(
        description="Monitor network device system health"
    )
    parser.add_argument(
        "-d", "--device", required=True, help="Device IP address or hostname"
    )
    parser.add_argument(
        "-u", "--user", required=True, help="SSH username"
    )
    parser.add_argument(
        "-p", "--password", help="SSH password (prompt if not provided)"
    )
    parser.add_argument(
        "--port", type=int, default=22, help="SSH port (default: 22)"
    )
    parser.add_argument(
        "--warn-cpu", type=float, default=80, help="CPU warning threshold %"
    )
    parser.add_argument(
        "--crit-cpu", type=float, default=95, help="CPU critical threshold %"
    )
    parser.add_argument(
        "--warn-mem", type=float, default=85, help="Memory warning threshold %"
    )
    parser.add_argument(
        "--crit-mem", type=float, default=95, help="Memory critical threshold %"
    )
    parser.add_argument(
        "--warn-disk", type=float, default=90, help="Disk warning threshold %"
    )
    parser.add_argument(
        "--crit-disk", type=float, default=98, help="Disk critical threshold %"
    )
    args = parser.parse_args()

    if not args.password:
        import getpass
        args.password = getpass.getpass("SSH Password: ")

    monitor = DeviceHealthMonitor(
        device=args.device,
        username=args.user,
        password=args.password,
        port=args.port,
    )
    sys.exit(
        monitor.run(
            warn_cpu=args.warn_cpu,
            crit_cpu=args.crit_cpu,
            warn_mem=args.warn_mem,
            crit_mem=args.crit_mem,
            warn_disk=args.warn_disk,
            crit_disk=args.crit_disk,
        )
    )


if __name__ == "__main__":
    main()
```