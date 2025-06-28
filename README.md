# soc-tools

A collection of tools for Security Operations Center (SOC) tasks, malware analysis, and threat detection.

## Tools
---

### 1. betterSIEM
**betterSIEM** is a reimplementation and enhancement of [IppSec's PowerSIEM](https://github.com/IppSec/PowerSiem), a PowerShell-based proof of concept tool designed to tail the Sysmon Event Log.

#### Purpose
I primarily use **PowerSIEM** to quickly find Indicators of Compromise (IOCs) for malware. The tool offers real-time visibility into Sysmon logs, making it easier to observe malicious behavior as it occurs. Although its usability is sub-par so I added the following features.

#### Enhancements Over PowerSIEM
- Rewritten parts of the script to improve usability and readability.
- Auto-elevates to administrator privileges.
- Logs output to disk for persistent analysis.
- Press `q` to gracefully exit and automatically open the log file in Visual Studio Code.

---

More tools will be added soon to this repository.
