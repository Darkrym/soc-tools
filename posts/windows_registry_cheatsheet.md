---
author:
  name: "Darkrym"
date: 2025-06-03
linktitle: Windows Registry
type:
- post
- posts
title: Windows Registry Cheat Sheet
weight: 10
series:
- cheat_sheets
---

This cheat sheet offers a concise guide to key Windows Registry locations and artefacts used in malware analysis, forensic investigations, and threat detection. It includes common persistence mechanisms, user activity traces, and system configuration paths, alongside valuable tips for hunting indicators of compromise (IOCs). Ideal for DFIR professionals and red/blue team operations.

---

## Key Hive Overview

| Hive                   | Abbreviation | Description           | File Location                  |
| ---------------------- | ------------ | --------------------- | ------------------------------ |
| **HKEY_LOCAL_MACHINE** | `HKLM`       | System-wide settings  | `%SystemRoot%\System32\Config` |
| **HKEY_CURRENT_USER**  | `HKCU`       | Current user settings | `C:\Users\[user]\NTUSER.DAT`   |
| **HKEY_USERS**         | `HKU`        | All loaded user hives | Mirrors `NTUSER.DAT`           |

---

## Static Analysis of HKCU

For forensics and general static analysis, `HKEY_CURRENT_USER` must be accessed through `HKEY_USERS` using the user’s **SID**:

Look up SIDs from one of these locations:

| Registry Path                                                           | Purpose           |
| ----------------------------------------------------------------------- | ----------------- |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`         | All user profiles |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI` | Most recent user  |

Replace:  
`HKCU\<Key>` ➝ `HKU\<SID>\<Key>`

---

## Persistence & Autostart Locations

| Key Purpose          | Registry Path                                                                                     | Common Misuse                        |
|----------------------|---------------------------------------------------------------------------------------------------|--------------------------------------|
| **Startup – Run key**         | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`                                               | Startup persistence                  |
| **RunOnce key**              | `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`                                           | One-time execution                   |
| **Services**                | `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`                                              | Malicious service creation           |
| **NSSM service config**     | `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters`                                  | NSSM-based persistence               |
| **Scheduled Tasks**         | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>`              | Scheduled task abuse                 |
| **Winlogon Shell key**      | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`                                 | Shell hijacking                      |
| **Image File Execution Options (IFEO)** | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<AppName>\Debugger` | Binary hijacking/debugger abuse     |

---

## User Activity

| Key Purpose         | Registry Path                                                                                   |
|---------------------|-------------------------------------------------------------------------------------------------|
| **Last logged-in user**     | `HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`                          |
| **Recent documents**        | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`                       |
| **Typed folder paths**      | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`                       |
| **Run dialog history**      | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`                           |
| **Mapped drives**           | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU`            |
| **RDP history**             | `HKU\<SID>\Software\Microsoft\Terminal Server Client\Default`                                   |

---

## System Information

| Description         | Registry Path                                                              |
|---------------------|-----------------------------------------------------------------------------|
| **RDP Enabled**              | `HKLM\System\CurrentControlSet\Control\Terminal Server\`                  |
| **System Timezone**          | `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`              |
| **USB Device History**       | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`                             |
| **Mounted Drives**          | `HKLM\SYSTEM\MountedDevices`                                            |

---

## Artefact Traces

| Artefact Type         | Registry Path                                                                 |
|------------------------|-------------------------------------------------------------------------------|
| **File extension behaviour** | `HKLM\Software\Classes\<file_extension>\Shell\Open\Command`                 |
|                          | `HKU\<SID>\Software\Classes\<file_extension>\Shell\Open\Command`             |
| **Environment Variables**    | `HKU\<SID>\Environment`, `HKLM\Environment`                               |

---

## Tools for Registry Analysis

| Tool             | Use                                           |
|------------------|-----------------------------------------------|
| **RegRipper**     | Plugin-based hive parser (automated)         |
| **Registry Explorer** | GUI-based visual inspection                |
| **RECmd**         | CLI registry exploration                     |
| **YARP**          | Python-based hive parser                     |
| **RegShot**       | Compare registry snapshots (before/after)    |

---

## Registry Threat Hunting Tips

Look for:
- Auto-start entries in suspicious paths
- IFEO hijacks without legitimate debugging reason
- Services with suspicious image paths or arguments
- Encoded/obfuscated payloads in values
- Unusual keys in `Run`, `RunOnce`, `Shell`

---

## Sysmon Registry Event IDs

| Event ID | Description                                |
|----------|--------------------------------------------|
| **12**   | Registry key object created or deleted     |
| **13**   | Registry value set                         |
| **14**   | Registry object renamed                    |
