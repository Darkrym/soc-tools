---
author:
  name: "Darkrym"
date: 2025-06-02
linktitle: Windows Log
type:
- post
- posts
title: Windows Log Analysis Cheat Sheet (+ Chainsaw)
weight: 10
series:
- cheat_sheets
---

This Windows Event Logs cheat sheet is designed for digital forensics, threat hunting, and security event analysis. It summarises critical Windows event IDs, logon types, and log source locations (Security.evtx, System.evtx, PowerShell logs, and more). Perfect for SOC analysts, incident responders, and malware investigators, this guide helps identify suspicious activity and map attack chains using native event logs.

---

## Important Event IDs by Log Source

### Security.evtx
`C:\Windows\System32\winevt\Logs\Security.evtx`  

```
4624 # Account successfully logged on (watch types 2, 3, 10, 11)
4625 # Account failed to log on (watch for error codes and type)
4634 # Account successfully logged off
4648 # Logon attempt using explicit credentials (pass-the-hash indicator)
4672 # Special privileges assigned to new logon (admin logon)
4688 # A new process has been created (monitor parent-child chains)
4697 # Service installation detected
4698 # Scheduled task creation
4699 # Scheduled task deletion
4700 # Scheduled task enabled
4701 # Scheduled task disabled
4702 # Scheduled task updated/modified
4720 # A user account was created
4722 # A user account was enabled
4723 # A user attempted to change password
4724 # A user reset another user’s password
4732 # Account added to a group
4733 # Account removed from a group
4736 # Account deleted
4738 # User account changed
4740 # A user account was locked out
4767 # A user account was unlocked
4768 # Kerberos authentication ticket (TGT) requested
4769 # Kerberos service ticket requested (TGS)
4770 # Kerberos service ticket renewed
4771 # Kerberos pre-authentication failed (watch for 0x18, 0x10, 0x17)
4776 # DC attempted to validate credentials
4778 # RDP session reconnected
4779 # RDP session disconnected
1102 # Audit log cleared (potential anti-forensic)
4614 # Security system extension loaded (can indicate new security packages)
```
## Logon Type Breakdown (4624 / 4625)

| Type | Description                                            |
| ---- | ------------------------------------------------------ |
| 0    | System (used internally by the OS)                     |
| 2    | Interactive (user at keyboard)                         |
| 3    | Network (SMB, RDP with NLA)                            |
| 4    | Batch (Scheduled Task)                                 |
| 5    | Service (Service account logon)                        |
| 7    | Unlock (user unlocked workstation)                     |
| 8    | NetworkCleartext (credentials sent in cleartext)       |
| 9    | NewCredentials (`RunAs /netonly`)                      |
| 10   | RemoteInteractive (Terminal Services/RDP)              |
| 11   | CachedInteractive (domain unreachable, cached creds)   |
| 12   | CachedRemoteInteractive (auditing remote cached login) |
| 13   | CachedUnlock (unlock using cached credentials)         |

---

### System.evtx
`C:\Windows\System32\winevt\Logs\System.evtx`

```
6005 # Event log service started (system boot)
6006 # Event log service stopped (clean shutdown)
6008 # Unexpected shutdown
7036 # Service state change
7040 # Service start type change (e.g., auto → manual)
7045 # New service installed
```

### Application.evtx

```
1000 # Application error (useful for malware crashing)
1026 # .NET Runtime error (malicious .NET payloads may trigger this)
App-specific # Look for entries from security tools (AV, EDR, backup failures, etc.)
```

### PowerShell Operational
`C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx` 

```
4100 # PowerShell engine state change
4103 # Module logging (e.g., internal commands, pipelines)
4104 # Script block logging (critical for threat hunting)
4105 # Script block rejected by policy
4106 # Script block execution started
```

### Windows Defender Operational 
`C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx`
```
1116  # Malware detected
1117  # Malware action taken (e.g. removed, quarantined)
1118  # Malware remediation failed
5001  # Real-time protection disabled
5004  # Real-time protection restored
5007  # Configuration change (may indicate tampering)
1006  # Scan started
1007  # Scan completed
```

### Sysmon.evtx
`C:\Windows\System32\winevt\Logs\Sysmon.evtx` 

```
1    # Process creation (command-line, parent, hashes) — must-have
3    # Network connection (IP, port, process) — beaconing, C2
7    # Image loaded (DLLs, LOLBins) — great for lateral movement/abuse
10   # Process access (injection, token theft) — attack surface
11   # File created (sensitive paths) — payload delivery
12   # Registry object created/deleted — persistence, tampering
13   # Registry value set — auto-run keys, config mods
22   # DNS query (process + domain) — domain-based IOCs
25   # Process tampering (hollowing, manipulation) — evasive malware
```

---


## Chainsaw Usage

### Basic Hunt

```bash
chainsaw hunt --directory ./evtx --rules ./sigma
```

---

### Search by Event ID

```bash
# Chainsaw v1
chainsaw search log.evtx -e 4104

# Chainsaw v2
chainsaw search log.evtx -t "Event.System.EventID: =4104"
```

---

### Search by String Match

```bash
# Chainsaw v1
chainsaw search log.evtx -s "IEX"

# Chainsaw v2
chainsaw search log.evtx -e "IEX"
```

---

### Timestamp Filtering

```bash
# Chainsaw v1 – string-based date filtering
chainsaw search ./ -s "2025-06-29"

# Chainsaw v2 – structured timestamp filtering
chainsaw search ./ \
  --timestamp Event.System.TimeCreated_attributes.SystemTime \
  --from 2022-06-21T00:00:00 \
  --to 2025-06-29T00:00:00
```

---

## Useful Chainsaw Searches

### Security.evtx

```
# 4624 - Logons
chainsaw search log.evtx -e 4624 -i -s "JoeBloggs" | grep -i "ipaddress" | sort | uniq -c | sort -nr           # Count all ip addresses obervered for a particular user
chainsaw search log.evtx -e 4624 -i -s "username_or_ip" | grep -iE "ipaddress|targetusername|logontype|systemtime"  # Show users or ip logon time and type Hint: remove "-i -s "Username/IP"" to show all users 

# 4625 - Failed Logons 
chainsaw search log.evtx -e 4625 | grep -i targetusername | sort | uniq -c | sort -nr         # Count Failed Logon for each user, useful for brute force
chainsaw search log.evtx -e 4625 -i -s "JoeBloggs" | grep -i systemtime                       # Display time for each logon for specific users 
```
### System.evtx

```
# 7045 - Service Creation
chainsaw search log.evtx -e 7045 -i -s "service_name" | grep -iE "ImagePath|ServiceName|SystemTime"           # Show Service Creation Details
```

### Powershell Operational 
```
# 4014 - Powershell Script Blocks
chainsaw search log.evtx -e 4104 | grep -i "scriptblocktext"               # Show just the clear text script block
chainsaw search log.evtx -e 4104 | grep -i "IEX" | sort | uniq -c          # Script blocks containing text "IEX" <- Change for desired string/command
```
- Look for `4104` events with:
  - `IEX`, `Invoke-WebRequest`, `New-Object`
  - Obfuscated/encoded strings (`FromBase64String`)
- Check for AMSI bypass or download cradle patterns
- Correlate with `4688` for execution chain context

---

## Useful Tools for Static Analysis

| Tool                  | Use                          |   
| --------------------- | ---------------------------- | 
| **Chainsaw**          | Fast hunting with Sigma      |   
| **EvtxECmd**          | Convert `.evtx` to CSV       |   
| **EventLog Explorer** | GUI log viewer               |   
| **KAPE**              | Forensic triage              |   
| **Sigma**             | Rule format used by Chainsaw |   
| **Hayabusa**          | Log Parser                   |   

---

