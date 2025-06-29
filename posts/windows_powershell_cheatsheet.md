---
author:
  name: "Darkrym"
date: 2025-06-08
linktitle: Windows CLI
type:
- post
- posts
title: Windows CLI Commands Cheat Sheet
weight: 10
series:
- cheat_sheets
---

This PowerShell cheat sheet is your fast-access reference for essential Windows CLI commands used in system administration, task automation, security auditing, and endpoint analysis. From file and process management to networking, scripting, and package control with Winget, this guide empowers both IT professionals and security analysts to work more efficiently with the Windows command line.

---

## Basics – File & Directory Operations

```powershell
pwd                     # Get-Location – Print current directory
ls                      # Get-ChildItem – List directory contents
ls -Force               # Get-ChildItem -Force – Include hidden files
cd C:\Path\To\Dir       # Set-Location – Change directory
cd ~                    # Set-Location ~ – Go to home/profile dir
cd ..                   # Go up one directory
mkdir NewFolder         # New-Item -ItemType Directory – Create folder
ni file.txt             # New-Item file.txt – Create empty file
cp source.txt dest.txt  # Copy-Item – Copy file
mv old.txt new.txt      # Move-Item – Move or rename
rm file.txt             # Remove-Item – Delete file
rm -r -fo folder        # Remove-Item -Recurse -Force – Delete folder recursively (dangerous)
```

---

## Search, Filters, and Viewing

```powershell
code file.txt              # Open in VSCode (Requires environment Var)
cat file.txt               # Get-Content – View file contents
cat file.txt | select -f 10  # Get-Content -Head 10 – First 10 lines
cat file.txt | select -l 10  # Get-Content -Tail 10 – Last 10 lines
sls "text" file.txt         # Select-String – Search text in file
ls -r -fi *.log             # Get-ChildItem -Recurse -Filter *.log – Find log files
```

---

## Sorting and Counting

```powershell
cat filename.txt | sort -u                          # Sort-Object | Get-Unique – Remove duplicates
cat filename.txt | group | sort Count -desc         # Group-Object | Sort-Object – Count + sort
sls "Search" filename.txt | sort -u                 # Search, sort, unique lines
```

---

## System Info & Processes

```powershell
systeminfo                              # Display all system information
ps                                      # Get-Process – List all processes
ps | ? {$_.Name -like "*app*"}          # Where-Object – Filter by name
While(1) {ps | sort -des cpu | select -f 15 | ft -a; sleep 1; cls}  # Real-time monitor
uptime                                  # Get-Uptime – System uptime (PowerShell 7+)
whoami                                  # whoami – Current user (native cmd)
hostname                                # hostname – System hostname
gcim Win32_OperatingSystem | select Version  # Get OS version
```

---

## Network Commands

```powershell
ipconfig                     # Network info
netstat -an                  # Active connections
netstat -anb                 # Add -b for process names
Get-NetTCPConnection         # List TCP connections
ping 8.8.8.8                 # Test network
iwr http://example.com       # Invoke-WebRequest – Fetch content
nslookup domain.com          # DNS lookup
```

---

## Permissions & Ownership

```powershell
icacls file.txt                  # View permissions
icacls file.txt /grant User:F   # Grant full permissions to User
takeown /f file.txt             # Take ownership
Start-Process powershell -v runAs  # Run as Administrator
```

---

## App & Service Management

```powershell
ii .                         # Invoke-Item . – Open folder in Explorer
ii file.pdf                  # Invoke-Item – Open file with default app
Start notepad.exe            # Start-Process – Launch app
kill -n notepad              # Stop-Process -Name – Kill by name
ps | ? {$_.MainWindowTitle -like "*text*"} | kill  # Filter + kill
```

---

## Package Managers

```powershell
winget install name          # Install package
winget upgrade               # Update all packages
winget list                  # List installed packages
winget uninstall name        # Uninstall package
```

---

## Scripting & Automation

```powershell
# Requires -Version X.0
'Hello Windows' | Out-Host

Set-ExecutionPolicy Unrestricted  # Allow scripts
Unblock-File .\hello.ps1 
.\hello.ps1                      # Run script
```

---

## Disk & Mounting

```powershell
Get-Volume                   # List volumes
mountvol                     # Volume mount info
Get-Disk                     # Physical disks
```

---

## File Hashing

```powershell
Get-FileHash file.txt                  # Compute SHA256 hash (default)
Get-FileHash file.txt -a SHA1          # Compute SHA1 hash
(Get-FileHash file.txt).Hash           # Output just the hash string

# Compare two files
if ((Get-FileHash file1.txt).Hash -eq (Get-FileHash file2.txt).Hash) {
    "Files are identical"
} else {
    "Files differ"
}
```

---

## Misc

```powershell
Get-Date                     # Show date/time
history                      # Get-History – Show command history
clear                        # Clear-Host – Clear screen
```

---

## Suggested Tools

| Tool             | Purpose                       |
|------------------|-------------------------------|
| **PowerToys**     | Productivity & window manager |
| **Windows Terminal** | Modern tabbed terminal       |
| **Winget**         | Official package manager      |
| **Sysinternals**   | Advanced diagnostics          |
| **Autoruns**       | Show auto-start programs      |
| **Process Explorer** | Visual process manager     |
