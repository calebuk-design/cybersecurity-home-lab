# Windows Firewall Configuration

## Overview
Firewall rules configured on the Windows Server VM to restrict attack surface and control traffic.

---

## Inbound Rules

### Block RDP from all except management IP
```powershell
# Remove default open RDP rule
netsh advfirewall firewall set rule name="Remote Desktop - User Mode (TCP-In)" new enable=no

# Allow RDP only from specific management IP
New-NetFirewallRule -DisplayName "RDP - Management Only" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 3389 `
  -RemoteAddress 192.168.56.20 `
  -Action Allow
```

### Block SMB from external (keep local only)
```powershell
New-NetFirewallRule -DisplayName "Block SMB Inbound External" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 445 `
  -RemoteAddress Any `
  -Action Block

New-NetFirewallRule -DisplayName "Allow SMB Local Network" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 445 `
  -RemoteAddress 192.168.56.0/24 `
  -Action Allow
```

### Block ICMP (ping) — optional for stealth
```powershell
New-NetFirewallRule -DisplayName "Block ICMP Inbound" `
  -Direction Inbound `
  -Protocol ICMPv4 `
  -Action Block
```

### Allow Splunk Web UI (port 8000) local only
```powershell
New-NetFirewallRule -DisplayName "Splunk Web - Local Only" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8000 `
  -RemoteAddress 192.168.56.0/24 `
  -Action Allow
```

---

## Outbound Rules

### Block outbound to internet (lab isolation)
```powershell
New-NetFirewallRule -DisplayName "Block All Outbound Internet" `
  -Direction Outbound `
  -RemoteAddress Internet `
  -Action Block
```

---

## Viewing Current Rules
```powershell
# List all active inbound rules
Get-NetFirewallRule -Direction Inbound -Enabled True | Select DisplayName, Action

# List all active outbound rules
Get-NetFirewallRule -Direction Outbound -Enabled True | Select DisplayName, Action
```

---

## Rule Summary Table

| Rule | Direction | Port | Action |
|------|-----------|------|--------|
| RDP - Management Only | Inbound | 3389 | Allow (192.168.56.20 only) |
| Block SMB External | Inbound | 445 | Block |
| Allow SMB Local | Inbound | 445 | Allow (192.168.56.0/24) |
| Block ICMP | Inbound | - | Block |
| Splunk Web | Inbound | 8000 | Allow (local only) |
| Block Internet Outbound | Outbound | All | Block |

---

## Key Takeaways
- Restricting RDP by source IP significantly reduces brute-force exposure
- SMB (445) should never be open to external networks
- Logging blocked connections in Splunk provides visibility into blocked attack attempts
