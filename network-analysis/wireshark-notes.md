# Wireshark Network Analysis Notes

## Useful Capture Filters

```
# Capture only traffic between the two VMs
host 192.168.56.10 and host 192.168.56.20

# Capture DNS traffic
port 53

# Capture HTTP/HTTPS
port 80 or port 443

# Capture RDP
port 3389
```

## Useful Display Filters

```
# Show only TCP SYN packets (start of connections)
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Show failed TCP connections (RST)
tcp.flags.reset == 1

# Filter by source IP
ip.src == 192.168.56.20

# Show ICMP (ping) traffic
icmp

# Show SMB traffic
smb or smb2

# Detect potential port scan (many SYNs, no ACKs)
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

## Observations

### Nmap SYN Scan
- Tool: `nmap -sS 192.168.56.10`
- Pattern: Rapid SYN packets to multiple ports in sequence
- In Wireshark: Many SYN packets from 192.168.56.20, RST responses from closed ports, SYN-ACK from open ports

### Open Ports Identified on Windows Server
| Port | Service | State |
|------|---------|-------|
| 135  | RPC     | Open  |
| 139  | NetBIOS | Open  |
| 445  | SMB     | Open  |
| 3389 | RDP     | Open  |
| 8000 | Splunk  | Open  |

## Key Takeaways
- SMB (445) and RDP (3389) are high-risk ports that should be restricted
- Wireshark SYN pattern is a reliable indicator of port scanning activity
- Baseline traffic capture is important before analysing anomalies
