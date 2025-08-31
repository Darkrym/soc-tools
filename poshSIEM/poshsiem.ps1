<# 
.SYNOPSIS
    Real-time Sysmon triage with JSON output.

.DESCRIPTION
    Watches Microsoft-Windows-Sysmon and prints only the fields you specify
    per Event ID in a PowerShell data file (.psd1). If no config exists,
    a safe baseline is created beside the script.

    Alerts print to console and also to a timestamped SysmonAlerts-YYYYMMDD-HHMMSS.log
    on the Desktop.

.PARAMETER ConfigPath
    Path to a .psd1 mapping Sysmon Event IDs (as strings) to an array of fields.

.PARAMETER NoOpen
    Do not open the log file in an editor on exit.

.NOTES
    Run as Administrator. Press q to quit.
    Tested on PowerShell 5.1 / 7 and Sysmon v14+.
#>

#requires -version 5.1

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path -Path ($(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location) })) -ChildPath 'poshsiem.psd1'),
    [switch]$NoOpen
)

# --- Auto-elevate -------------------------------------------------------------
function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = [Security.Principal.WindowsPrincipal]::new($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

if (-not (Test-IsAdministrator)) {
    if (-not $PSCommandPath) {
        Write-Host "Please save this script as a .ps1 file so it can relaunch itself with elevation." -ForegroundColor Red
        exit 1
    }

    # Rebuild the argument list, preserving your original parameters and switches
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`""
    )

    foreach ($kvp in $PSBoundParameters.GetEnumerator()) {
        $name = $kvp.Key
        $val  = $kvp.Value

        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val.IsPresent) { $argList += "-$name" }
        }
        elseif ($null -ne $val -and "$val" -ne '') {
            $escaped = ($val.ToString() -replace '"','`"')
            $argList += "-$name"
            $argList += "`"$escaped`""
        }
    }

    # If the caller didn't bind -ConfigPath, still pass the resolved default so elevation keeps it
    if (-not $PSBoundParameters.ContainsKey('ConfigPath') -and ($null -ne $ConfigPath) -and ($ConfigPath -ne '')) {
        $escapedConfig = ($ConfigPath -replace '"','`"')
        $argList += '-ConfigPath'
        $argList += "`"$escapedConfig`""
    }

    # Pass through any unbound args as well
    foreach ($a in $args) { $argList += $a }

    # Prefer pwsh if available, otherwise fallback to Windows PowerShell
    $exe = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }

    $proc = Start-Process -FilePath $exe `
        -ArgumentList ($argList -join ' ') `
        -Verb RunAs `
        -PassThru `
        -WorkingDirectory (Get-Location)

    $proc.WaitForExit()
    exit $proc.ExitCode
}
# --- End auto-elevate ---------------------------------------------------------


# --- Default config content (rich schema with names and toggles) --------------
$DefaultConfig = @'
@{
    # You can comment out any whole block to disable it, or set Enabled = $false

    "1"  = @{ Name='Process Create';             Enabled=$true; Fields=@("ProcessId","Image","CommandLine","CurrentDirectory","User","ParentImage") }
    "2"  = @{ Name='File Creation Time Changed'; Enabled=$true; Fields=@("ProcessId","Image","TargetFileName","CreationUtcTime","PreviousCreationUtcTime") }
    "3"  = @{ Name='Network Connection';         Enabled=$true; Fields=@("Image","DestinationIp","DestinationPort","Protocol","Initiated") }
    "5"  = @{ Name='Process Terminated';         Enabled=$true; Fields=@("ProcessId","Image") }
    "6"  = @{ Name='Driver Loaded';              Enabled=$true; Fields=@("ImageLoaded","Hashes","Signature","Signed") }
    "7"  = @{ Name='Image Load';                 Enabled=$true; Fields=@("Image","Hashes","Signature","Signed") }
    "8"  = @{ Name='Create Remote Thread';       Enabled=$true; Fields=@("SourceProcessId","SourceImage","TargetProcessId","TargetImage","StartAddress") }
    "9"  = @{ Name='Raw Access Read';            Enabled=$true; Fields=@("Image","ProcessId","Device") }
    "10" = @{ Name='Process Access';             Enabled=$true; Fields=@("SourceProcessId","SourceImage","TargetProcessId","TargetImage","GrantedAccess","CallTrace") }
    "11" = @{ Name='File Create';                Enabled=$true; Fields=@("TargetFileName","User","Image","ProcessId") }
    "12" = @{ Name='Registry Object Added/Deleted'; Enabled=$true; Fields=@("EventType","Image","ProcessId","TargetObject") }
    "13" = @{ Name='Registry Value Set';         Enabled=$true; Fields=@("ProcessId","Image","TargetObject","Details") }
    "14" = @{ Name='Registry Object Renamed';    Enabled=$true; Fields=@("Image","ProcessId","OldName","NewName") }
    "15" = @{ Name='File Create Stream Hash';    Enabled=$true; Fields=@("Image","ProcessId","TargetFileName","Hashes") }
    "16" = @{ Name='Sysmon Configuration Change';Enabled=$true; Fields=@("Image","ProcessId","Configuration") }
    "17" = @{ Name='Pipe Created';               Enabled=$true; Fields=@("Image","ProcessId","PipeName") }
    "18" = @{ Name='Pipe Connected';             Enabled=$true; Fields=@("Image","ProcessId","PipeName") }
    "19" = @{ Name='WMI Event Filter Activity';  Enabled=$true; Fields=@("Image","ProcessId","Operation","EventNamespace","Name","Query") }
    "20" = @{ Name='WMI Event Consumer Activity';Enabled=$true; Fields=@("Image","ProcessId","Operation","Name","Type") }
    "21" = @{ Name='WMI Filter-to-Consumer Binding'; Enabled=$true; Fields=@("Image","ProcessId","Operation","Consumer","Filter") }
    "22" = @{ Name='DNS Query';                  Enabled=$true; Fields=@("QueryName", "QueryResults","Image","ProcessId") }
    "23" = @{ Name='File Delete';                Enabled=$true; Fields=@("TargetFileName","Image","ProcessId") }
    "24" = @{ Name='Clipboard Event';            Enabled=$true; Fields=@("Image","ProcessId","Session","ClientInfo","CapturedData") }
    "25" = @{ Name='Process Tampering Detected'; Enabled=$true; Fields=@("TamperType","Image","TargetImage") }
    "26" = @{ Name='File Delete Logged';         Enabled=$true; Fields=@("TargetFileName","User","Image","ProcessId") }
}
'@

# --- Load configuration -------------------------------------------------------
if (Test-Path -LiteralPath $ConfigPath) {
    try {
        $FieldMap = Import-PowerShellDataFile -Path $ConfigPath
    } catch {
        Write-Error "Failed to load config at '$ConfigPath': $($_.Exception.Message). Using built-in defaults."
        try {
            $FieldMap = Invoke-Expression $DefaultConfig
        } catch {
            Write-Error "Failed to load embedded default config: $($_.Exception.Message)"
            exit 1
        }
    }
} else {
    Write-Error "No config file found at '$ConfigPath'. Using built-in defaults."
    try {
        $FieldMap = Invoke-Expression $DefaultConfig
    } catch {
        Write-Error "Failed to load embedded default config: $($_.Exception.Message)"
        exit 1
    }
}

# --- Normalise config: support rich blocks and legacy arrays ------------------
# Builds $Config = @{ "ID" = @{ Name='...', Enabled=bool, Fields=[string[]](...) } }
# --- Normalise config: support rich blocks and legacy arrays ------------------
$Config = @{}
foreach ($kv in $FieldMap.GetEnumerator()) {
    $id  = [string]$kv.Key
    $val = $kv.Value

    if ($val -is [hashtable]) {
        $name    = if ($val.ContainsKey('Name'))    { [string]$val.Name }    else { "Event $id" }
        $enabled = if ($val.ContainsKey('Enabled')) { [bool]  $val.Enabled } else { $true }
        $fields  = if ($val.ContainsKey('Fields'))  { [string[]]$val.Fields } else { [string[]]@() }
        $colour  = if ($val.ContainsKey('Colour'))  { [string]$val.Colour }  else { $null }

        $Config[$id] = @{
            Name    = $name
            Enabled = $enabled
            Fields  = [string[]]$fields
            Colour  = $colour
        }
    }
    elseif ($val -is [string]) {
        $Config[$id] = @{
            Name    = "Event $id"
            Enabled = $true
            Fields  = [string[]]@($val)
            Colour  = $null
        }
    }
    elseif ($val -is [System.Collections.IEnumerable]) {
        $Config[$id] = @{
            Name    = "Event $id"
            Enabled = $true
            Fields  = [string[]]@($val)
            Colour  = $null
        }
    }
}


# --- Logging ------------------------------------------------------------------
$desktop = [Environment]::GetFolderPath('Desktop')
$runTag  = Get-Date -Format 'yyyyMMdd-HHmmss'   # unique per run
$logName = "SysmonAlerts-$runTag.log"
$logFile = Join-Path $desktop $logName

"Sysmon Alert Log - Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')`n-----" |
  Set-Content -Path $logFile -Encoding UTF8

# --- Helpers ------------------------------------------------------------------
function Parse-Event {
    param([Parameter(ValueFromPipeline=$true)] $Event)
    process {
        foreach ($entry in $Event) {
            try {
                $xml = [xml]$entry.ToXml()
                foreach ($node in $xml.Event.EventData.Data) {
                    $name  = $node.name
                    $value = $node.'#text'
                    if ($name) {
                        $entry | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
                    }
                }
            } catch { }
            $entry
        }
    }
}

function Build-ConfiguredAlert {
    param([int]$EventId, [psobject]$Evt)

    $key = [string]$EventId
    if (-not $Config.ContainsKey($key)) { return $null }

    $ci = $Config[$key]
    if (-not $ci.Enabled) { return $null }

    $fields = [string[]]$ci.Fields
    if (-not $fields -or $fields.Count -eq 0) { return $null }

    $eventName = if ($ci.Name) { $ci.Name } else { "Event $key" }

    $output = [ordered]@{
        Type        = ('{0} (ID {1})' -f $eventName, $EventId)
        EventId     = $EventId
        TimeCreated = ($Evt.TimeCreated | Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        RecordId    = $Evt.RecordId
        Colour      = $ci.Colour
        __Allowed   = [string[]]$fields
    }

    $added = $false
    foreach ($field in $fields) {
        if ($Evt.PSObject.Properties.Match($field).Count -gt 0) {
            $val = $Evt.$field
            if ($null -ne $val -and "$val" -ne '') {
                $output[$field] = "$val"
                $added = $true
            }
        }
    }

    if ($added) { return $output } else { return $null }
}

function Write-Alert {
    param([hashtable]$Alert)
    if (-not $Alert) { return }

    $allowed = @()
    if ($Alert.ContainsKey('__Allowed')) { $allowed = @($Alert.__Allowed) }

    # Text mode: colour only the Type line
    $typeColour = if ($Alert.Colour) { [string]$Alert.Colour } else { 'Yellow' }
    try {
        # Validate colour name against ConsoleColor
        $null = [ConsoleColor]([Enum]::Parse([ConsoleColor], $typeColour, $true))
    } catch {
        $typeColour = 'Yellow'
    }

    # Build the text for the log file (not coloured)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("Type: $($Alert.Type)")
    $null = $sb.AppendLine("")

    foreach ($f in $allowed) {
        if ($Alert.ContainsKey($f)) {
            $null = $sb.AppendLine(("{0}: {1}" -f $f, $Alert[$f]))
        }
    }
    $null = $sb.AppendLine("-----")
    $txt = $sb.ToString()

    # Console output with colour on the header line only
    Write-Host ("Type: {0}" -f $Alert.Type) -ForegroundColor $typeColour
    Write-Host ""
    foreach ($f in $allowed) {
        if ($Alert.ContainsKey($f)) {
            Write-Host ("{0}: {1}" -f $f, $Alert[$f])
        }
    }
    Write-Host "-----"

    # Persist full text to the log file
    Add-Content -Path $logFile -Value $txt -Encoding UTF8
}


# --- Event stream setup -------------------------------------------------------
$provider = "Microsoft-Windows-Sysmon"

try {
    $latest = Get-WinEvent -ProviderName $provider -Max 1 -ErrorAction Stop
} catch {
    Write-Host "Could not read events from provider '$provider'. Is Sysmon installed and running?" -ForegroundColor Red
    exit 1
}
$maxRecordId = $latest.RecordID
Write-Host "Monitoring Sysmon events. Press q to quit." -ForegroundColor Cyan

# --- Non-blocking single-key quit --------------------------------------------
$prevTreat = [console]::TreatControlCAsInput
[console]::TreatControlCAsInput = $true
try {
    while ($true) {
        Start-Sleep -Milliseconds 300

        if ([console]::KeyAvailable) {
            $k = [console]::ReadKey($true)
            if ($k.Key -eq [ConsoleKey]::Q) { break }
        }

        $xPath = "*[System[EventRecordID > $maxRecordId]]"
        try {
            $logs = Get-WinEvent -ProviderName $provider -FilterXPath $xPath -ErrorAction Stop |
                    Sort-Object RecordID
        } catch { continue }

        foreach ($log in $logs) {
            $evt = $log | Parse-Event
            $eid = 0; try { $eid = [int]$evt.Id } catch { }

            $alert = Build-ConfiguredAlert -EventId $eid -Evt $evt
            if ($alert) { Write-Alert $alert }

            $maxRecordId = $evt.RecordId
        }
    }
}
finally {
    [console]::TreatControlCAsInput = $prevTreat
}

if (-not $NoOpen) {
    Write-Host "Exiting and opening log file..." -ForegroundColor Cyan
    try {
        if (Get-Command code -ErrorAction SilentlyContinue) { code $logFile }
        else { Start-Process notepad.exe $logFile | Out-Null }
    } catch { }
}
