<#
.SYNOPSIS
    PowerSIEM Sysmon field map and alert toggles.

.DESCRIPTION
    Each Event ID maps to a hashtable with:
      Name    = Friendly display name
      Enabled = $true / $false
      Fields  = Array of fields to capture, one per line
      Colour  = ConsoleColor for the “Type: …” line

.NOTES
    - Comment out fields individually to disable them.
    - Set Enabled = $false to disable an event.
#>

@{
    "1" = @{
        Name    = 'Process Create'
        Enabled = $true
        Colour  = 'Magenta'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            # "FileVersion"
            # "Description"
            # "Product"
            # "Company"
            "CommandLine"
            "CurrentDirectory"
            "User"
            # "LogonGuid"
            # "LogonId"
            # "TerminalSessionId"
            # "IntegrityLevel"
            # "Hashes"
            #"ParentProcessGuid"
            "ParentImage"
            # "ParentCommandLine"
        )
    }

    "2" = @{
        Name    = 'File Creation Time Changed'
        Enabled = $true
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            "TargetFileName"
            # "CreationUtcTime"
            # "PreviousCreationUtcTime"
        )
    }

    "3" = @{
        Name    = 'Network Connection'
        Enabled = $true
        Colour  = 'Magenta'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            # "User"
            # "Protocol"
            # "Initiated"
            # "SourceIsIpv6"
            # "SourceIp"
            # "SourceHostname"
            # "SourcePort"
            # "SourcePortName"
            "DestinationIp"
            # "DestinationIsIpv6"
            "DestinationPort"
            # "DestinationHostname"
            # "DestinationPortName"
        )
    }

    "5" = @{
        Name    = 'Process Terminated'
        Enabled = $true
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
        )
    }

    "6" = @{
        Name    = 'Driver Loaded'
        Enabled = $true
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            "ImageLoaded"
            "Hashes"
            # "Signed"
            "Signature"
            # "SignatureStatus"
        )
    }

    "7" = @{
        Name    = 'Image Load'
        Enabled = $true
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            "Image"
            "ImageLoaded"
            "Hashes"
            # "Signed"
            "Signature"
            # "SignatureStatus"
            # "ProcessGuid"
            # "ProcessId"
        )
    }

    "8" = @{
        Name    = 'Create Remote Thread'
        Enabled = $true
        Colour  = 'Red'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            "SourceProcessId"
            "SourceImage"
            "TargetProcessId"
            "TargetImage"
            # "SourceProcessGuid"
            # "TargetProcessGuid"
            # "NewThreadId"
            # "StartAddress"
            # "StartModule"
            # "StartFunction"
        )
    }

    "9" = @{
        Name    = 'Raw Access Read'
        Enabled = $false
        Colour  = 'Red'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            "Device"
        )
    }

    "10" = @{
        Name    = 'Process Access'
        Enabled = $true
        Colour  = 'Red'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            "SourceProcessId"
            "SourceImage"
            "TargetProcessId"
            "TargetImage"
            # "SourceProcessGuid"
            # "TargetProcessGuid"
            # "GrantedAccess"
            # "CallTrace"
        )
    }

    "11" = @{
        Name    = 'File Create'
        Enabled = $true
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            "TargetFilename"
            # "CreationUtcTime"
            #"User"
        )
    }

    "12" = @{
        Name    = 'Registry Object Added/Deleted'
        Enabled = $false
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "EventType"
            # "UtcTime"
            # "ProcessGuid"
            # "ProcessId"
            # "Image"
            # "TargetObject"
            # "User"
        )
    }

    "13" = @{
        Name    = 'Registry Value Set'
        Enabled = $true
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "EventType"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            "TargetObject"
            "Details"
            # "User"
        )
    }

    "14" = @{
        Name    = 'Registry Object Renamed'
        Enabled = $false
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "EventType"
            # "UtcTime"
            # "ProcessGuid"
            # "ProcessId"
            # "Image"
            "TargetObject"
            "NewName"
            # "User"
        )
    }

    "15" = @{
        Name    = 'File Create Stream Hash'
        Enabled = $false
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            # "ProcessId"
            # "Image"
            "TargetFilename"
            # "CreationUtcTime"
            "Hashes"
        )
    }

    "16" = @{
        Name    = 'Sysmon Configuration Change'
        Enabled = $true
        Colour  = 'Red'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            "Configuration"
            "ConfigurationFileHash"
        )
    }

    "17" = @{
        Name    = 'Pipe Created'
        Enabled = $false
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            # "ProcessId"
            "PipeName"
            "Image"
        )
    }

    "18" = @{
        Name    = 'Pipe Connected'
        Enabled = $false
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            # "ProcessId"
            "PipeName"
            "Image"
        )
    }

    "19" = @{
        Name    = 'WMI Event Filter Activity'
        Enabled = $false
        Colour  = 'Red'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            "EventNamespace"
            "Name"
            "Query"
        )
    }

    "20" = @{
        Name    = 'WMI Event Consumer Activity'
        Enabled = $false
        Colour  = 'Red'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            "Name"
            "Type"
            # "Destination"
        )
    }

    "21" = @{
        Name    = 'WMI Consumer to Filter Binding'
        Enabled = $false
        Colour  = 'Red'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            "Consumer"
            "Filter"
        )
    }

    "22" = @{
        Name    = 'DNS Query'
        Enabled = $true
        Colour  = 'Magenta'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "QueryName"
            # "QueryStatus"
            "QueryResults"
            "Image"
            # "User"
        )
    }

    "23" = @{
        Name    = 'File Delete'
        Enabled = $true
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            "TargetFilename"
            # "User"
        )
    }

    "24" = @{
        Name    = 'Clipboard Event'
        Enabled = $false
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            # "SessionId"
            # "ClientInfo"
            "ClipboardEventType"
            # "CapturedData"
        )
    }

    "25" = @{
        Name    = 'Process Tampering'
        Enabled = $true
        Colour  = 'Red'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            "TamperType"
            # "TargetProcessGuid"
            # "TargetProcessId"
            "TargetImage"
        )
    }

    "26" = @{
        Name    = 'File Delete Logged'
        Enabled = $true
        Colour  = 'Yellow'
        Fields  = @(
            # "RuleName"
            # "UtcTime"
            # "ProcessGuid"
            "ProcessId"
            "Image"
            "TargetFilename"
            "User"
        )
    }
}
