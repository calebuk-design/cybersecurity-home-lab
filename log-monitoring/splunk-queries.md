# Splunk Log Monitoring Queries

## Data Sources
- Windows Security Event Log (EventCode)
- Windows System Event Log
- Splunk index: `index=main` or `index=wineventlog`

---

## Authentication & Login Monitoring

### Failed Login Attempts
```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, IpAddress, Failure_Reason
| sort -count
```

### Successful Logins
```spl
index=wineventlog EventCode=4624
| stats count by Account_Name, Logon_Type, IpAddress
| sort -count
```

### Brute Force Detection (10+ failures in 5 minutes)
```spl
index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count by _time, Account_Name, IpAddress
| where count > 10
```

---

## Privilege & Account Changes

### Account Created
```spl
index=wineventlog EventCode=4720
| table _time, Account_Name, Subject_Account_Name
```

### User Added to Privileged Group
```spl
index=wineventlog EventCode=4728 OR EventCode=4732 OR EventCode=4756
| table _time, Account_Name, Group_Name, Subject_Account_Name
```

### Privilege Escalation Attempt
```spl
index=wineventlog EventCode=4672
| stats count by Account_Name
| sort -count
```

---

## Process & System Activity

### New Process Created
```spl
index=wineventlog EventCode=4688
| table _time, Account_Name, New_Process_Name, Creator_Process_Name
```

### Suspicious PowerShell Execution
```spl
index=wineventlog EventCode=4688 New_Process_Name="*powershell*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
```

---

## Firewall & Network Events

### Windows Firewall — Blocked Connections
```spl
index=wineventlog EventCode=5152
| stats count by SourceAddress, DestAddress, DestPort
| sort -count
```

### RDP Connection Attempts
```spl
index=wineventlog EventCode=4624 Logon_Type=10
| stats count by Account_Name, IpAddress
```

---

## Useful Event Code Reference

| EventCode | Description |
|-----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4672 | Special privileges assigned |
| 4688 | New process created |
| 4720 | User account created |
| 4728 | User added to global group |
| 5152 | Firewall blocked packet |
