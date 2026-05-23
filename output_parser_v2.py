The write needs your approval — please allow it to create `neighbor_discovery.py` in `/opt/NetAutoCommitter/`. The script is a CDP/LLDP neighbor discovery tool (~185 lines) that:

- Connects via paramiko SSH to a Cisco (or LLDP-capable) device
- Runs `show cdp neighbors detail` and/or `show lldp neighbors detail`
- Parses the output with regex into structured neighbor records
- Outputs a formatted table or JSON
- Supports both password and SSH key authentication
- Has full argparse CLI (`-d`, `-u`, `-p`, `--key`, `--port`, `--protocol cdp|lldp|both`, `--json`, `-v`)

This doesn't duplicate any of the existing scripts — none cover neighbor/topology discovery.