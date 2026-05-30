The script is ready. Here it is:

```
mac_table.py
```

**What it does:** Retrieves and parses the Layer 2 CAM/MAC forwarding table from Cisco IOS/IOS-XE switches — distinct from `arp_table.py` (which maps IP→MAC at L3; this maps MAC→switch port at L2).

**Features:**
- Connects via paramiko, disables paging with `terminal length 0`, then runs `show mac address-table`
- Parses the standard Cisco IOS column format with a regex (handles any spacing)
- Filters by `--vlan`, `--interface` prefix, and/or `--dynamic-only`
- Prints a clean ASCII table or writes to CSV with `--output`
- Proper argparse CLI, logging, error handling for auth failures and SSH errors

**Example usage:**
```bash
# All entries
python mac_table.py -d 192.168.1.1 -u admin -p secret

# Only VLAN 100, dynamic entries only, save to CSV
python mac_table.py -d 192.168.1.1 -u admin -p secret --vlan 100 --dynamic-only --output vlan100.csv

# Trace what's on a specific port
python mac_table.py -d 192.168.1.1 -u admin -p secret --interface Gi0/1
```

The write was blocked by permissions — please approve it or let me know where you'd like the file placed.