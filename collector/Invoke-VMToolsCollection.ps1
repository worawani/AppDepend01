<#
.SYNOPSIS
    Deploys and harvests the AppDepend collector through vCenter and VMware Tools
    (no WinRM or SMB to the guest needed).

.DESCRIPTION
    Uses VMware PowerCLI (Invoke-VMScript and Copy-VMGuestFile). The traffic goes
    vCenter -> ESXi -> VMware Tools, so it works for VMs in firewalled segments
    and DMZs where WinRM is blocked from the jump host.

    Requirements:
      * VMware PowerCLI on the jump host (Install-Module VMware.PowerCLI)
      * VMware Tools running in each guest
      * A vCenter account with the privileges
        VirtualMachine.GuestOperations.{Query,Modify,Execute}
      * Local admin guest credentials for the Windows VMs

    Modes are the same as Invoke-RemoteCollection.ps1: Deploy, Collect, Remove, Status.

.EXAMPLE
    Connect-VIServer vcsa01.corp.local
    $guest = Get-Credential CORP\svc-migration
    .\Invoke-VMToolsCollection.ps1 -Mode Deploy  -VMName (Get-Content .\wave2.txt) -GuestCredential $guest
    .\Invoke-VMToolsCollection.ps1 -Mode Collect -VMName (Get-Content .\wave2.txt) -GuestCredential $guest -LocalPath D:\AppDepend\collected

.EXAMPLE
    # Every powered-on Windows VM in a cluster:
    $vms = Get-Cluster PROD-CL01 | Get-VM | Where-Object { $_.PowerState -eq 'PoweredOn' -and $_.Guest.OSFullName -like '*Windows*' }
    .\Invoke-VMToolsCollection.ps1 -Mode Deploy -VM $vms -GuestCredential $guest
#>
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Deploy', 'Collect', 'Remove', 'Status')][string]$Mode,
    [Parameter(ParameterSetName = 'ByName', Mandatory = $true)][string[]]$VMName,
    [Parameter(ParameterSetName = 'ByObject', Mandatory = $true)][object[]]$VM,
    [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$GuestCredential,
    [string]$LocalPath = (Join-Path (Get-Location) 'collected'),
    [string]$RemotePath = 'C:\AppDepend',
    [ValidateRange(1, 59)][int]$SampleMinutes = 58,
    [ValidateRange(2, 3600)][int]$IntervalSeconds = 15,
    [switch]$PurgeData
)

$ErrorActionPreference = 'Stop'
if ($RemotePath -match '\s') { throw '-RemotePath must not contain spaces (it is used in a Scheduled Task command line).' }
if (-not (Get-Command Invoke-VMScript -ErrorAction SilentlyContinue)) {
    throw 'VMware PowerCLI is not loaded. Install-Module VMware.PowerCLI; Connect-VIServer <vcenter>'
}
$collector = Join-Path $PSScriptRoot 'Collect-AppDependency.ps1'
$taskName = 'AppDepend-Collector'
$out = Join-Path $RemotePath 'out'

if ($PSCmdlet.ParameterSetName -eq 'ByName') {
    $VM = @($VMName | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { Get-VM -Name $_.Trim() })
}

function Invoke-Guest($vmObj, [string]$Text) {
    $r = Invoke-VMScript -VM $vmObj -GuestCredential $GuestCredential -ScriptType Powershell -ScriptText $Text -ErrorAction Stop
    if ($r.ExitCode -ne 0) { throw "exit $($r.ExitCode): $($r.ScriptOutput)" }
    return $r.ScriptOutput
}

foreach ($v in $VM) {
    try {
        if ($v.PowerState -ne 'PoweredOn') { Write-Warning "[$($v.Name)] skipped: $($v.PowerState)"; continue }
        switch ($Mode) {
            'Deploy' {
                Invoke-Guest $v "New-Item -ItemType Directory -Force -Path '$RemotePath','$out' | Out-Null" | Out-Null
                Copy-VMGuestFile -VM $v -GuestCredential $GuestCredential -LocalToGuest -Source $collector -Destination "$RemotePath\" -Force
                # A .cmd wrapper keeps quotes out of /TR (PS 5.1 mangles embedded quotes passed to native exes).
                Invoke-Guest $v @"
`$cmd = '@echo off' + [char]13 + [char]10 + 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$RemotePath\Collect-AppDependency.ps1" -OutputPath "$out" -DurationMinutes $SampleMinutes -IntervalSeconds $IntervalSeconds -Append > "$RemotePath\last-run.log" 2>&1' + [char]13 + [char]10
[IO.File]::WriteAllText('$RemotePath\run-collector.cmd', `$cmd, (New-Object Text.ASCIIEncoding))
schtasks.exe /Create /F /TN $taskName /RU SYSTEM /RL HIGHEST /SC HOURLY /MO 1 /ST 00:00 /TR $RemotePath\run-collector.cmd | Out-Null
if (`$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }
schtasks.exe /Run /TN $taskName | Out-Null
"@ | Out-Null
                Write-Host "[$($v.Name)] deployed"
            }
            'Collect' {
                $files = (Invoke-Guest $v "Get-ChildItem -Path '$out' -Filter *.csv -ErrorAction SilentlyContinue | ForEach-Object { `$_.Name }") -split "`r?`n" | Where-Object { $_.Trim() }
                $dir = Join-Path $LocalPath $v.Name
                if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                foreach ($f in $files) {
                    Copy-VMGuestFile -VM $v -GuestCredential $GuestCredential -GuestToLocal -Source "$out\$($f.Trim())" -Destination "$dir\" -Force
                }
                Write-Host "[$($v.Name)] collected $(@($files).Count) file(s)"
            }
            'Status' {
                $s = Invoke-Guest $v @"
`$q = schtasks.exe /Query /TN $taskName /FO CSV /V 2>`$null | ConvertFrom-Csv
`$i = Get-ChildItem '$out' -Filter *_hostinfo.csv -ErrorAction SilentlyContinue | Select-Object -First 1 | Import-Csv
'{0} | last run {1} | samples {2} | window {3} -> {4}' -f `$(if (`$q) { @(`$q)[0].Status } else { 'NOT INSTALLED' }), `$(if (`$q) { @(`$q)[0].'Last Run Time' }), `$(if (`$i) { `$i.Samples } else { 0 }), `$(if (`$i) { `$i.CollectionStart }), `$(if (`$i) { `$i.CollectionEnd })
"@
                Write-Host "[$($v.Name)] $($s.Trim())"
            }
            'Remove' {
                $purge = if ($PurgeData) { "Remove-Item -Recurse -Force '$RemotePath' -ErrorAction SilentlyContinue" } else { '' }
                Invoke-Guest $v "schtasks.exe /Delete /F /TN $taskName 2>`$null | Out-Null; $purge" | Out-Null
                Write-Host "[$($v.Name)] removed"
            }
        }
    } catch {
        Write-Warning "[$($v.Name)] $($_.Exception.Message)"
    }
}
