---
author:
  name: "Darkrym"
date: 2025-06-16
linktitle: MacOS CLI
type:
- post
- posts
title: MacOS CLI Commands Cheat Sheet
weight: 10
series:
- cheat_sheets
---

This macOS Terminal cheat sheet summarises critical shell commands and scripting techniques for macOS users involved in administration, development, and security tasks. It covers file system navigation, process monitoring, networking, Homebrew usage, and system security settings like Gatekeeper and SIP. Ideal for Apple-focused sysadmins, DFIR practitioners, and macOS power users.

---

## Basics – File & Directory Operations

```bash
pwd                     # Print current directory
ls                      # List directory contents
ls -la                  # Long listing incl. hidden files
cd /path/to/dir         # Change directory
cd ~                    # Home directory
cd -                    # Previous directory
cd ..                   # Up one directory
mkdir newfolder         # Create folder
touch file.txt          # Create empty file
cp source dest          # Copy files or directories
mv old new              # Move/rename
rm file.txt             # Delete file
rm -rf folder/          # Recursively delete folder (dangerous)
```

---

## Search, Filters, and Viewing

```bash
nano file.txt           # Open file in nano text editor
cat file.txt            # View file contents
less file.txt           # Scrollable file viewer
head -n 10 file.txt     # First 10 lines
tail -n 10 file.txt     # Last 10 lines
grep "text" file.txt    # Search text in file
find . -name "*.log"    # Find all .log files from current dir
```

---

## Sorting and Counting

```bash
sort filename.txt | uniq                         # Remove duplicate lines
sort filename.txt | uniq -c                      # Count occurrences of each unique line
sort filename.txt | uniq -c | sort -nr           # Count and sort by most frequent
cat filename.txt | grep -i "Search" | sort | uniq  # Filter, sort, then remove duplicates
```

---

## System Info & Processes

```bash
top                     # Real-time system monitor
ps aux                  # List all running processes
ps -ef | grep name      # Search process list
uptime                  # System uptime
whoami                  # Current user
hostname                # System hostname
sw_vers                 # macOS version
```

---

## Network Commands

```bash
ifconfig                # Network interfaces
netstat -an             # Network connections
lsof -i :port           # Processes using a specific port
ping 8.8.8.8            # ICMP test
curl http://example.com # Fetch content from URL
dig domain.com          # DNS lookup
```

---

## Permissions & Ownership

```bash
chmod +x script.sh      # Make file executable
chmod 755 file          # rwxr-xr-x (owner can write/execute)
chown user:group file   # Change file owner
sudo su                 # Switch to root (if enabled)
sudo -s                 # Root shell
```

---

## App & Service Management

```bash
open .                  # Open Finder at current path
open file.pdf           # Open with default app
open -a "App Name"      # Open app from CLI
killall Safari          # Kill app by name
pkill -f processname    # Kill by process string match
```

---

## Package Managers

```bash
brew install packagename       # Install software
brew update && brew upgrade    # Update packages
brew list                      # List installed packages
brew uninstall packagename     # Remove package
```

---

## Gatekeeper, SIP & Security Controls

> These can weaken system security. Use with understanding and caution.

```bash
# Remove quarantine attribute from downloaded files (Safer then below)
xattr -d com.apple.quarantine /path/to/script  

# Disable Gatekeeper
sudo spctl --master-disable

# Check Gatekeeper status
sudo spctl --status

# Re-enable Gatekeeper
sudo spctl --master-enable
```

> Must be done from Recovery Mode to disable SIP:

```bash
# Disable SIP
csrutil disable

# Re-enable SIP
csrutil enable
```

```bash
# Disable TCC for a specific app (not recommended unless testing)
tccutil reset All com.app.bundleid
```

---

## Scripting & Automation

```bash
#!/bin/bash
echo "Hello macOS"

# Make script executable and run
chmod +x script.sh
./script.sh
```

---

## Hidden Files & System Files

```bash
# Show hidden files
defaults write com.apple.finder AppleShowAllFiles -bool true
killall Finder

# Hide hidden files
defaults write com.apple.finder AppleShowAllFiles -bool false
killall Finder
```

---

## Disk & Mounting

```bash
diskutil list                     # List all disks/partitions
diskutil mount /dev/disk2s1      # Mount disk
diskutil unmount /dev/disk2s1    # Unmount disk
```

---

## Passwords & Keychain

```bash
security find-generic-password -ga "accountname"  # Show saved password (may prompt)
```

---

## Misc

```bash
date                       # Show date/time
history                    # Show command history
clear                      # Clear terminal screen
```

---

## Suggested Tools

| Tool          | Purpose                         |
|---------------|----------------------------------|
| **Homebrew**  | Package manager                  |
| **Little Snitch** | Network monitor             |
| **KnockKnock**| Persistency inspector            |
| **BlockBlock**| Detects auto-run locations       |
| **osquery**   | Query OS like a database         |
