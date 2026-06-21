I need permission to write the file. Once you approve, here's the script I'll create — `mac_table.py`, a MAC address table collector that:

- Connects to one or more Cisco IOS/IOS-XE devices via paramiko SSH
- Parses `show mac address-table` output with regex
- Supports searching for a specific MAC (accepts any common format: colons, dashes, dotted-quad, plain hex)
- Supports filtering by VLAN
- Prints a clean tabular report

This fills a genuine gap — none of the existing scripts touch the MAC table, and it's a daily-use tool for network engineers tracing where a device is physically connected.