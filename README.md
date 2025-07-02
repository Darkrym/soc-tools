# soc-tools

A collection of tools for Security Operations Center (SOC) tasks, malware analysis, and threat detection.

## Tools
---

### 1. betterSIEM
**betterSIEM** is a reimplementation and enhancement of [IppSec's PowerSIEM](https://github.com/IppSec/PowerSiem), a PowerShell-based proof of concept tool designed to tail the Sysmon Event Log.

#### Purpose
I primarily used **PowerSIEM** to quickly find Indicators of Compromise (IOCs) for malware. The tool offers real-time visibility into Sysmon logs, making it easier to observe malicious behavior as it occurs. Although its usability is sub-par so I added the following features.

#### Enhancements Over PowerSIEM
- Rewritten parts of the script to improve usability and readability.
- Auto-elevates to administrator privileges.
- Logs output to disk for persistent analysis.
- Press `q` to gracefully exit and automatically open the log file in Visual Studio Code.

#### Prerequisites 
- Sysmon - Find it [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- A Good Sysmon Config - I highly recommend Florian Roth's ([here](https://github.com/bakedmuffinman/Neo23x0-sysmon-config)) as he is the GOAT of detection logic
---

### 2. OpenScanner

**OpenScanner** is a Python-based OSINT tool for scanning and analysing domains, IP addresses, and URLs. It automates reputation checks, DNS resolution, WHOIS lookups, passive intelligence gathering, and safe payload interaction.

#### Features
- Separates logic for domains and IPs
- IP & domain enrichment using:
  - **AbuseIPDB**
  - **GreyNoise**
  - **VirusTotal**
  - **Shodan**
  - **Censys**
  - **URLScan.io**
  - **crt.sh**
  - **SecurityTrails**
  - **IPVoid**
  - **WHOIS**
- Identifies:
  - Domain age & suspicious WHOIS patterns
  - Cloud-hosted or anonymised infra
  - VPN/proxy/TOR tags
  - Redirect chains and short URL destinations
- Command-line flags for `--verbose` and `--expand` modes

#### Prerequisites
- API keys for each service (**VirusTotal** and **Shodan** require **paid** accounts)
- Python 3.10+
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```
---

More tools will be added soon to this repository.
