The script is ready — here's what it produces once you approve the write:

**`vlan_audit.py`** — 185 lines, parses `show vlan brief` + `show interfaces trunk` to map every VLAN to its access ports and trunk members. Not covered by any existing script in the repo.

Key design decisions:
- `_expand_port_range()` handles Cisco compact notation (`Gi0/1-3, Fa0/5` → flat list)
- `parse_interfaces_trunk()` reads the "Vlans allowed on trunk" section specifically (not the native or active sections, which would double-count)
- `--vlan ID` filters to a single VLAN for quick spot-checks
- `--json` emits machine-parseable output for pipeline use
- Paramiko `invoke_shell` + `terminal length 0` mirrors real terminal behavior to avoid paginated output truncation

Please approve the file write to place it at `/opt/NetAutoCommitter/vlan_audit.py`.