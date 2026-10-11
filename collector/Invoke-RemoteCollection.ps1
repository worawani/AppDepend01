<#
.SYNOPSIS
    Deploys, harvests, and removes the AppDepend collector on many Windows
    servers over WinRM (PowerShell Remoting).

.DESCRIPTION
    Run from an admin/jump host that can reach the targets on WinRM (5985/5986).
    The targets only need PowerShell 3.0+ (Windows Server 2012 and later).

    Modes:
      Deploy   Copy the collector to C:\AppDepend on each target and register a
               Scheduled Task (SYSTEM) that samples -SampleMinutes every hour.
               This is the recommended long-running mode (2-4 weeks).
      Collect  Pull all CSVs back from each target into -LocalPath\<HOST>\ .
               Safe to run at any time; the task keeps running.
      Remove   Delete the Scheduled Task, and with -PurgeData also C:\AppDepend.
      RunOnce  Run the collector synchronously for -SampleMinutes on all
               targets in parallel, then Collect. Quick for a pilot, but too
               short to plan waves from.
      Status   Show task state and last collection time per target.

    If WinRM is blocked, use Invoke-VMToolsCollection.ps1 instead. It goes
    through vCenter and VMware Tools and needs no guest network access.

.PARAMETER ComputerName
    One or more target hostnames/IPs. Use -ComputerListFile for a list.

.PARAMETER ComputerListFile
    Text file with one host per line (lines starting with # are ignored), or a
    CSV with a column named VM, Name, ComputerName or Hostname.

.EXAMPLE
    $cred = Get-Credential CORP\svc-migration
    .\Invoke-RemoteCollection.ps1 -Mode Deploy  -ComputerListFile .\wave2.txt -Credential $cred
    .\Invoke-RemoteCollection.ps1 -Mode Status  -ComputerListFile .\wave2.txt -Credential $cred
    .\Invoke-RemoteCollection.ps1 -Mode Collect -ComputerListFile .\wave2.txt -Credential $cred -LocalPath D:\AppDepend\collected
    .\Invoke-RemoteCollection.ps1 -Mode Remove  -ComputerListFile .\wave2.txt -Credential $cred -PurgeData
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Deploy', 'Collect', 'Remove', 'RunOnce', 'Status')][string]$Mode,
    [string[]]$ComputerName,
    [string]$ComputerListFile,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$LocalPath = (Join-Path (Get-Location) 'collected'),
    [string]$RemotePath = 'C:\AppDepend',
    [ValidateRange(1, 59)][int]$SampleMinutes = 58,
    [ValidateRange(2, 3600)][int]$IntervalSeconds = 15,
    [switch]$UseSSL,
    [switch]$PurgeData,
    [int]$ThrottleLimit = 32
)

$ErrorActionPreference = 'Stop'
if ($RemotePath -match '\s') { throw '-RemotePath must not contain spaces (it is used in a Scheduled Task command line).' }
$collector = Join-Path $PSScriptRoot 'Collect-AppDependency.ps1'
$taskName = 'AppDepend-Collector'

# ---------------------------------------------------------------- targets
$targets = @()
if ($ComputerName) { $targets += $ComputerName }
if ($ComputerListFile) {
    if ($ComputerListFile -like '*.csv') {
        foreach ($row in (Import-Csv $ComputerListFile)) {
            foreach ($col in 'VM', 'Name', 'ComputerName', 'Hostname') {
                if ($row.PSObject.Properties[$col] -and $row.$col) { $targets += $row.$col; break }
            }
        }
    } else {
        $targets += Get-Content $ComputerListFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }
    }
}
$targets = @($targets | Select-Object -Unique)
if ($targets.Count -eq 0) { throw 'No targets. Use -ComputerName or -ComputerListFile.' }

$sessionArgs = @{ ComputerName = $targets; ThrottleLimit = $ThrottleLimit; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'remoteErrors' }
if ($Credential) { $sessionArgs.Credential = $Credential }
if ($UseSSL) { $sessionArgs.UseSSL = $true }

function Write-RemoteErrors($errs) {
    foreach ($e in @($errs)) {
        $target = if ($e.TargetObject) { $e.TargetObject } elseif ($e.OriginInfo) { $e.OriginInfo.PSComputerName } else { '?' }
        Write-Warning ("[{0}] {1}" -f $target, $e.Exception.Message)
    }
}

Write-Host "Mode $Mode on $($targets.Count) target(s)"

switch ($Mode) {
    'Deploy' {
        $scriptText = Get-Content -Path $collector -Raw
        $remoteErrors = $null
        Invoke-Command @sessionArgs -ArgumentList $scriptText, $RemotePath, $taskName, $SampleMinutes, $IntervalSeconds -ScriptBlock {
            param($ScriptText, $Path, $TaskName, $Minutes, $Interval)
            if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
            $scriptFile = Join-Path $Path 'Collect-AppDependency.ps1'
            Set-Content -Path $scriptFile -Value $ScriptText -Encoding UTF8
            $out = Join-Path $Path 'out'
            # A .cmd wrapper keeps quotes out of /TR (PS 5.1 mangles embedded quotes passed to native exes).
            $cmdFile = Join-Path $Path 'run-collector.cmd'
            $cmdText = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptFile`" -OutputPath `"$out`" -DurationMinutes $Minutes -IntervalSeconds $Interval -Append > `"$Path\last-run.log`" 2>&1`r`n"
            [IO.File]::WriteAllText($cmdFile, $cmdText, (New-Object Text.ASCIIEncoding))
            # schtasks.exe works on every Windows Server version from 2012 on, unlike the ScheduledTasks module.
            & schtasks.exe /Create /F /TN $TaskName /RU SYSTEM /RL HIGHEST /SC HOURLY /MO 1 /ST 00:00 /TR $cmdFile | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "schtasks /Create failed with $LASTEXITCODE" }
            & schtasks.exe /Run /TN $TaskName | Out-Null
            "$env:COMPUTERNAME deployed; first sample running now"
        } | ForEach-Object { Write-Host "  $_" }
        Write-RemoteErrors $remoteErrors
    }

    'RunOnce' {
        $remoteErrors = $null
        $out = Join-Path $RemotePath 'out'
        Invoke-Command @sessionArgs -FilePath $collector -ArgumentList $out, $SampleMinutes, $IntervalSeconds | Out-Host
        Write-RemoteErrors $remoteErrors
        & $PSCommandPath -Mode Collect -ComputerName $targets -Credential $Credential -LocalPath $LocalPath -RemotePath $RemotePath -UseSSL:$UseSSL
    }

    'Collect' {
        if (-not (Test-Path $LocalPath)) { New-Item -ItemType Directory -Path $LocalPath -Force | Out-Null }
        $remoteErrors = $null
        # Send file contents back through the remoting channel, which works with PS 3.0 targets
        # (Copy-Item -FromSession needs PS 5 at both ends).
        $results = Invoke-Command @sessionArgs -ArgumentList (Join-Path $RemotePath 'out') -ScriptBlock {
            param($Out)
            if (-not (Test-Path $Out)) { return }
            Get-ChildItem -Path $Out -Filter '*.csv' | ForEach-Object {
                New-Object PSObject -Property @{ Name = $_.Name; Content = [IO.File]::ReadAllText($_.FullName) }
            }
        }
        foreach ($r in @($results)) {
            $dir = Join-Path $LocalPath $r.PSComputerName
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            [IO.File]::WriteAllText((Join-Path $dir $r.Name), $r.Content, (New-Object Text.UTF8Encoding($true)))
        }
        $hosts = @($results | Select-Object -ExpandProperty PSComputerName -Unique)
        Write-Host "  Collected $(@($results).Count) file(s) from $($hosts.Count) host(s) into $LocalPath"
        $missing = @($targets | Where-Object { $hosts -notcontains $_ })
        if ($missing.Count) { Write-Warning ("No data from: " + ($missing -join ', ')) }
        Write-RemoteErrors $remoteErrors
    }

    'Status' {
        $remoteErrors = $null
        Invoke-Command @sessionArgs -ArgumentList $taskName, (Join-Path $RemotePath 'out') -ScriptBlock {
            param($TaskName, $Out)
            $q = & schtasks.exe /Query /TN $TaskName /FO CSV /V 2>$null | ConvertFrom-Csv
            $info = Join-Path $Out "$($env:COMPUTERNAME)_hostinfo.csv"
            $hi = if (Test-Path $info) { Import-Csv $info | Select-Object -First 1 } else { $null }
            New-Object PSObject -Property ([ordered]@{
                Host = $env:COMPUTERNAME
                Task = $(if ($q) { @($q)[0].Status } else { 'NOT INSTALLED' })
                LastRun = $(if ($q) { @($q)[0].'Last Run Time' } else { '' })
                CollectionStart = $(if ($hi) { $hi.CollectionStart } else { '' })
                CollectionEnd = $(if ($hi) { $hi.CollectionEnd } else { '' })
                Samples = $(if ($hi) { $hi.Samples } else { 0 })
            })
        } | Select-Object Host, Task, LastRun, CollectionStart, CollectionEnd, Samples | Format-Table -AutoSize | Out-Host
        Write-RemoteErrors $remoteErrors
    }

    'Remove' {
        $remoteErrors = $null
        Invoke-Command @sessionArgs -ArgumentList $taskName, $RemotePath, [bool]$PurgeData -ScriptBlock {
            param($TaskName, $Path, $Purge)
            & schtasks.exe /Delete /F /TN $TaskName 2>$null | Out-Null
            if ($Purge -and (Test-Path $Path)) { Remove-Item -Path $Path -Recurse -Force }
            "$env:COMPUTERNAME removed" + $(if ($Purge) { ' (data purged)' } else { '' })
        } | ForEach-Object { Write-Host "  $_" }
        Write-RemoteErrors $remoteErrors
    }
}
