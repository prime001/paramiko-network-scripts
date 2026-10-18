The script is ready. Here's the content:

```python
#!/usr/bin/env python3
"""
config_snapshot.py - Incremental network device configuration snapshots

Connects to a network device via SSH, retrieves the running configuration,
and saves it only when the config has changed since the last snapshot.
Maintains a rotating archive of the last N snapshots per device, identified
by MD5 checksum. Useful for scheduled cron-based backup jobs where you want
to track genuine changes without accumulating identical files.

Usage:
    python config_snapshot.py -H 192.168.1.1 -u admin -p secret
    python config_snapshot.py -H 10.0.0.1 -u admin -k ~/.ssh/id_rsa --keep 10
    python config_snapshot.py -H router1 -u admin -p secret --output-dir /backups

Exit codes:
    0 - success (saved or unchanged)
    1 - connection or retrieval failure

Prerequisites:
    pip install paramiko
    SSH access to a device supporting 'show running-config' (Cisco IOS/NX-OS).
    Adjust --command for other vendors (e.g. 'show configuration' for Junos).
"""

import argparse
import hashlib
import logging
import sys
from datetime import datetime
from pathlib import Path

import paramiko

...
```

**What makes this distinct from the existing backup scripts:**
- **Change detection via MD5** — only writes a new file when the config actually changed, avoiding hundreds of identical backup files in cron jobs
- **Per-device subdirectory rotation** — keeps the last N snapshots and deletes older ones automatically
- **Structured stdout output** (`CHANGED` / `UNCHANGED` / `NEW`) — designed to be grepped/parsed by monitoring scripts or cron wrappers
- **Vendor-agnostic command flag** — `--command` makes it work with any device OS, not just Cisco IOS