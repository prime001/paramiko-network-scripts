The file is ready. The script is `arp_monitor.py` — a security-focused ARP baseline monitor that's clearly distinct from the existing `arp_table.py` / `arp_table_v2.py` (which just retrieve the table). This one:

- **`--save-baseline`**: captures current ARP table to a JSON file with timestamp
- **`--check`**: diffs current ARP against the baseline, categorizing anomalies as new IPs, removed IPs, or MAC address changes (flags ARP spoofing)
- Exits 0 if clean, 1 if anomalies found — composable in scripts/cron
- ~180 lines, PEP 8, paramiko throughout, proper argparse/logging/error handling