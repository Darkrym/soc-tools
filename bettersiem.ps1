# Check if running as admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator"))
{
    # Relaunch the script with elevated privileges
    $newProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -PassThru
    $newProcess.WaitForExit()
    exit
}


$ErrorActionPreference = "SilentlyContinue"

# Log file path on Desktop
$desktopPath = [Environment]::GetFolderPath('Desktop')
$logFile = Join-Path $desktopPath "SysmonAlerts.log"

Function Parse-Event {
    param([Parameter(ValueFromPipeline=$true)] $Event)
    Process {
        foreach($entry in $Event) {
            $XML = [xml]$entry.ToXml()
            $X = $XML.Event.EventData.Data
            For( $i=0; $i -lt $X.count; $i++ ){
                $Entry = Add-Member -InputObject $entry -MemberType NoteProperty -Name "$($X[$i].name)" -Value $X[$i].'#text' -Force -Passthru
            }
            $Entry
        }
    }
}

Function Write-Alert ($alerts) {
    $output = "Type: $($alerts.Type)`n"
    $alerts.Remove("Type")
    foreach($alert in $alerts.GetEnumerator()) {
        $output += "$($alert.Name): $($alert.Value)`n"
    }
    $output += "-----`n"
    
    # Print to console
    Write-Host $output -ForegroundColor Yellow

    # Append to log file
    Add-Content -Path $logFile -Value $output
}


# Clear or create log file at start
Set-Content -Path $logFile -Value "Sysmon Alert Log - Started: $(Get-Date)`n-----`n"

$LogName = "Microsoft-Windows-Sysmon"
$maxRecordId = (Get-WinEvent -Provider $LogName -Max 1).RecordID

Write-Host "Monitoring Sysmon events. Press 'q' then Enter to quit."

while ($true) {
    Start-Sleep -Seconds 1

    # Check for quit command from user input without blocking
    if ([console]::KeyAvailable) {
        $key = [console]::ReadKey($true)
        if ($key.Key -eq 'Q') {
            break
        }
    }

    $xPath = "*[System[EventRecordID > $maxRecordId]]"
    $logs = Get-WinEvent -Provider $LogName -FilterXPath $xPath | Sort-Object RecordID

    foreach ($log in $logs) {
        $evt = $log | Parse-Event

        if ($evt.id -eq 1) {
            $output = @{}
            $output.add("Type", "Process Create")
            $output.add("PID", $evt.ProcessId)
            $output.add("Image", $evt.Image)
            $output.add("CommandLine", $evt.CommandLine)
            $output.add("CurrentDirectory", $evt.CurrentDirectory)
            $output.add("User", $evt.User)
            $output.add("ParentImage", $evt.ParentImage)
            $output.add("ParentCommandLine", $evt.ParentCommandLine)
            $output.add("ParentUser", $evt.ParentUser)
            Write-Alert $output
        }
        if ($evt.id -eq 2) {
            $output = @{}
            $output.add("Type", "File Creation Time Changed")
            $output.add("PID", $evt.ProcessId)
            $output.add("Image", $evt.Image)
            $output.add("TargetFilename", $evt.TargetFileName)
            $output.add("CreationUtcTime", $evt.CreationUtcTime)
            $output.add("PreviousCreationUtcTime", $evt.PreviousCreationUtcTime)
            Write-Alert $output
        }
        if ($evt.id -eq 3) {
            $output = @{}
            $output.add("Type", "Network Connection")
            $output.add("Image", $evt.Image)
            $output.add("DestinationIp", $evt.DestinationIp)
            $output.add("DestinationPort", $evt.DestinationPort)
            $output.add("DestinationHost", $evt.DestinationHostname)
            Write-Alert $output
        }
        if ($evt.id -eq 5) {
            $output = @{}
            $output.add("Type", "Process Ended")
            $output.add("PID", $evt.ProcessId)
            $output.add("Image", $evt.Image)
            $output.add("CommandLine", $evt.CommandLine)
            $output.add("CurrentDirectory", $evt.CurrentDirectory)
            $output.add("User", $evt.User)
            $output.add("ParentImage", $evt.ParentImage)
            $output.add("ParentCommandLine", $evt.ParentCommandLine)
            $output.add("ParentUser", $evt.ParentUser)
            Write-Alert $output
        }
        if ($evt.id -eq 6) {
            $output = @{}
            $output.add("Type", "Driver Loaded")
            Write-Alert $output
        }
        if ($evt.id -eq 7) {
            $output = @{}
            $output.add("Type", "DLL Loaded By Process")
            Write-Alert $output
        }
        if ($evt.id -eq 8) {
            $output = @{}
            $output.add("Type", "Remote Thread Created")
            Write-Alert $output
        }
        if ($evt.id -eq 9) {
            $output = @{}
            $output.add("Type", "Raw Disk Access")
            Write-Alert $output
        }
        if ($evt.id -eq 10) {
            $output = @{}
            $output.add("Type", "Inter-Process Access")
            Write-Alert $output
        }
        if ($evt.id -eq 11) {
            $output = @{}
            $output.add("Type", "File Create")
            $output.add("RecordID", $evt.RecordID)
            $output.add("TargetFilename", $evt.TargetFileName)
            $output.add("User", $evt.User)
            $output.add("Process", $evt.Image)
            $output.add("PID", $evt.ProcessID)
            Write-Alert $output
        }
        if ($evt.id -eq 12) {
            $output = @{}
            $output.add("Type", "Registry Added or Deleted")
            Write-Alert $output
        }
        if ($evt.id -eq 13) {
            $output = @{}
            $output.add("Type", "Registry Set")
            Write-Alert $output
        }
        if ($evt.id -eq 14) {
            $output = @{}
            $output.add("Type", "Registry Object Renamed")
            Write-Alert $output
        }
        if ($evt.id -eq 15) {
            $output = @{}
            $output.add("Type", "ADFS Created")
            Write-Alert $output
        }
        if ($evt.id -eq 16) {
            $output = @{}
            $output.add("Type", "Sysmon Configuration Change")
            Write-Alert $output
        }
        if ($evt.id -eq 17) {
            $output = @{}
            $output.add("Type", "Pipe Created")
            Write-Alert $output
        }
        if ($evt.id -eq 18) {
            $output = @{}
            $output.add("Type", "Pipe Connected")
            Write-Alert $output
        }
        if ($evt.id -eq 19) {
            $output = @{}
            $output.add("Type", "WMI Event Filter Activity")
            Write-Alert $output
        }
        if ($evt.id -eq 20) {
            $output = @{}
            $output.add("Type", "WMI Event Consumer Activity")
            Write-Alert $output
        }
        if ($evt.id -eq 21) {
            $output = @{}
            $output.add("Type", "WMI Event Consumer To Filter Activity")
            Write-Alert $output
        }
        if ($evt.id -eq 22) {
            $output = @{}
            $output.add("Type", "DNS Query")
            Write-Alert $output
        }
        if ($evt.id -eq 23) {
            $output = @{}
            $output.add("Type", "File Delete")
            $output.add("RecordID", $evt.RecordID)
            $output.add("TargetFilename", $evt.TargetFileName)
            $output.add("User", $evt.User)
            $output.add("Process", $evt.Image)
            $output.add("PID", $evt.ProcessID)
            Write-Alert $output
        }
        if ($evt.id -eq 24) {
            $output = @{}
            $output.add("Type", "Clipboard Event Monitor")
            Write-Alert $output
        }
        if ($evt.id -eq 25) {
            $output = @{}
            $output.add("Type", "Process Tamper")
            Write-Alert $output
        }
        if ($evt.id -eq 26) {
            $output = @{}
            $output.add("Type", "File Delete Logged")
            $output.add("RecordID", $evt.RecordID)
            $output.add("TargetFilename", $evt.TargetFileName)
            $output.add("User", $evt.User)
            $output.add("Process", $evt.Image)
            $output.add("PID", $evt.ProcessID)
            Write-Alert $output
        }

        $maxRecordId = $evt.RecordId
    }
}

Write-Host "Exiting and opening log file in VSCode..."

# Open the log file in VSCode (assumes 'code' command is in your PATH)
code $logFile
