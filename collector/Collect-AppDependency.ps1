<#
.SYNOPSIS
    Collects application network dependencies on a Windows Server by sampling
    TCP connections over time.

.DESCRIPTION
    Runs locally on the target VM (Windows Server 2012 / 2012 R2 / 2016 / 2019 /
    2022 / 2025, PowerShell 3.0+). Every -IntervalSeconds it snapshots TCP
    connections, maps each one to its owning process and Windows service, works
    out whether the connection is inbound (to a local listener) or outbound, and
    aggregates the results. Ephemeral ports are dropped, so 10,000 connections to
    SQL on 1433 become one row with a sample count.

    The output is four CSV files per host, which the Python analyzer (appdepend) reads:
        <HOST>_connections.csv   aggregated inbound/outbound flows
        <HOST>_listeners.csv     listening TCP ports and their process/service
        <HOST>_services.csv      running non-Microsoft services (app fingerprint)
        <HOST>_hostinfo.csv      host identity, IPs, OS, collection window

    -Append merges a new run into existing files, so you can run the script from
    a Scheduled Task (for example 58 minutes of every hour for 2-4 weeks) and get a
    single cumulative picture. Run it across a month-end so you catch batch jobs.

    Read-only: the script changes nothing on the host except writing to -OutputPath.

.PARAMETER OutputPath
    Folder for the CSV output. Created if it does not exist.

.PARAMETER DurationMinutes
    How long to sample in this run. Default 60.

.PARAMETER IntervalSeconds
    Seconds between snapshots. Default 15. Shorter catches more short-lived
    connections at slightly higher CPU cost (still negligible).

.PARAMETER Append
    Merge this run into existing output files instead of overwriting them.

.PARAMETER IncludeLoopback
    Keep 127.0.0.0/8 and ::1 connections (excluded by default).

.EXAMPLE
    .\Collect-AppDependency.ps1 -OutputPath C:\AppDepend -DurationMinutes 60

.EXAMPLE
    # Scheduled Task, every hour, 58-minute sampling, cumulative:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\AppDepend\Collect-AppDependency.ps1 -OutputPath C:\AppDepend\out -DurationMinutes 58 -Append
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:SystemDrive 'AppDepend'),
    [ValidateRange(1, 100000)][int]$DurationMinutes = 60,
    [ValidateRange(2, 3600)][int]$IntervalSeconds = 15,
    [switch]$Append,
    [switch]$IncludeLoopback
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$CollectorVersion = '1.0.0'

# ---------------------------------------------------------------- helpers

function Get-WmiData([string]$Class, [string]$Filter) {
    # Get-CimInstance exists from PS 3.0 and in PS 7; Get-WmiObject is the fallback for unusual hosts.
    $a = @{ ClassName = $Class; ErrorAction = 'Stop' }
    if ($Filter) { $a.Filter = $Filter }
    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        try { return @(Get-CimInstance @a) } catch { Write-Verbose "CIM $Class failed: $($_.Exception.Message)" }
    }
    $w = @{ Class = $Class; ErrorAction = 'Stop' }
    if ($Filter) { $w.Filter = $Filter }
    return @(Get-WmiObject @w)
}

function Test-IsLoopback([string]$Address) {
    return ($Address -like '127.*' -or $Address -eq '::1' -or $Address -like '::ffff:127.*')
}

function Test-IsUnspecified([string]$Address) {
    return ($Address -eq '0.0.0.0' -or $Address -eq '::' -or $Address -eq '*' -or [string]::IsNullOrEmpty($Address))
}

function ConvertTo-PlainIPv4([string]$Address) {
    # IPv4-mapped IPv6 (::ffff:10.1.2.3) -> 10.1.2.3
    if ($Address -like '::ffff:*' -and $Address -match '(\d{1,3}\.){3}\d{1,3}$') { return $Matches[0] }
    return $Address
}

function Split-Endpoint([string]$Endpoint) {
    # netstat formats: 10.0.0.1:445   [fe80::1%4]:445   *:*
    if ($Endpoint -match '^\[(.+)\]:(\d+|\*)$') { return @($Matches[1], $Matches[2]) }
    $idx = $Endpoint.LastIndexOf(':')
    if ($idx -lt 0) { return @($Endpoint, '0') }
    return @($Endpoint.Substring(0, $idx), $Endpoint.Substring($idx + 1))
}

$script:UseNetTcpCmdlet = $null
function Get-TcpSnapshot {
    <# Returns objects with LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess.
       Prefers Get-NetTCPConnection (WS2012+); falls back to parsing netstat -ano. #>
    if ($null -eq $script:UseNetTcpCmdlet) {
        $script:UseNetTcpCmdlet = [bool](Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
    }
    if ($script:UseNetTcpCmdlet) {
        try {
            return @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
                New-Object PSObject -Property @{
                    LocalAddress  = [string]$_.LocalAddress
                    LocalPort     = [int]$_.LocalPort
                    RemoteAddress = [string]$_.RemoteAddress
                    RemotePort    = [int]$_.RemotePort
                    State         = [string]$_.State
                    OwningProcess = [int]$_.OwningProcess
                }
            })
        } catch {
            Write-Verbose "Get-NetTCPConnection failed ($($_.Exception.Message)); using netstat."
            $script:UseNetTcpCmdlet = $false
        }
    }
    $rows = @()
    foreach ($line in (& netstat.exe -ano -p TCP) + (& netstat.exe -ano -p TCPv6)) {
        $parts = ($line.Trim() -split '\s+')
        if ($parts.Count -lt 5 -or $parts[0] -ne 'TCP') { continue }
        $l = Split-Endpoint $parts[1]; $r = Split-Endpoint $parts[2]
        $state = switch ($parts[3]) {
            'LISTENING'    { 'Listen' }
            'ESTABLISHED'  { 'Established' }
            'TIME_WAIT'    { 'TimeWait' }
            'CLOSE_WAIT'   { 'CloseWait' }
            'SYN_SENT'     { 'SynSent' }
            'SYN_RECEIVED' { 'SynReceived' }
            'FIN_WAIT_1'   { 'FinWait1' }
            'FIN_WAIT_2'   { 'FinWait2' }
            'LAST_ACK'     { 'LastAck' }
            'CLOSING'      { 'Closing' }
            default        { $parts[3] }
        }
        $rport = 0; [void][int]::TryParse($r[1], [ref]$rport)
        $rows += New-Object PSObject -Property @{
            LocalAddress = ($l[0] -replace '%\d+$', ''); LocalPort = [int]$l[1]
            RemoteAddress = ($r[0] -replace '%\d+$', ''); RemotePort = $rport
            State = $state; OwningProcess = [int]$parts[4]
        }
    }
    return $rows
}

function Get-ProcessServiceMap {
    # PID -> @{ Name; Path; Services }
    $map = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = ''
        try { $path = [string]$p.Path } catch { }
        $map[[int]$p.Id] = @{ Name = $p.ProcessName; Path = $path; Services = @() }
    }
    try {
        foreach ($s in (Get-WmiData Win32_Service "State='Running'")) {
            $id = [int]$s.ProcessId
            if ($map.ContainsKey($id)) { $map[$id].Services += $s.Name }
        }
    } catch { Write-Verbose "Win32_Service query failed: $($_.Exception.Message)" }
    return $map
}

function Get-LocalIPs {
    $ips = @()
    try {
        $ips = @(Get-WmiData Win32_NetworkAdapterConfiguration 'IPEnabled=TRUE' |
                 ForEach-Object { $_.IPAddress } | Where-Object { $_ -and -not (Test-IsLoopback $_) -and $_ -notlike 'fe80*' })
    } catch { }
    return @($ips | Select-Object -Unique)
}

function Import-Existing([string]$Path) {
    if ($Append -and (Test-Path $Path)) { return @(Import-Csv -Path $Path) }
    return @()
}

function Format-Time([datetime]$t) { return $t.ToString('yyyy-MM-ddTHH:mm:ss') }

# ---------------------------------------------------------------- setup

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$hostName = $env:COMPUTERNAME
$domain = ''
$os = ''; $osVersion = ''
try {
    $cs = @(Get-WmiData Win32_ComputerSystem)[0]
    $domain = [string]$cs.Domain
    $osObj = @(Get-WmiData Win32_OperatingSystem)[0]
    $os = [string]$osObj.Caption; $osVersion = [string]$osObj.Version
} catch { }
$fqdn = if ($domain) { "$hostName.$domain" } else { $hostName }
$localIPs = Get-LocalIPs

$connFile  = Join-Path $OutputPath "${hostName}_connections.csv"
$listFile  = Join-Path $OutputPath "${hostName}_listeners.csv"
$svcFile   = Join-Path $OutputPath "${hostName}_services.csv"
$infoFile  = Join-Path $OutputPath "${hostName}_hostinfo.csv"

# Aggregation tables, seeded from previous runs when -Append is used.
$conns = @{}
foreach ($r in (Import-Existing $connFile)) {
    $key = '{0}|{1}|{2}|{3}' -f $r.Direction, $r.RemoteAddress, $r.Port, $r.ProcessName
    $conns[$key] = @{
        Direction = $r.Direction; RemoteAddress = $r.RemoteAddress; Port = [int]$r.Port
        ProcessName = $r.ProcessName; ProcessPath = $r.ProcessPath; ServiceNames = $r.ServiceNames
        States = $r.States; FirstSeen = $r.FirstSeen; LastSeen = $r.LastSeen
        SampleCount = [int]$r.SampleCount; MaxConcurrent = [int]$r.MaxConcurrent
    }
}
$listeners = @{}
foreach ($r in (Import-Existing $listFile)) {
    $listeners["$($r.LocalAddress)|$($r.LocalPort)"] = @{
        LocalAddress = $r.LocalAddress; LocalPort = [int]$r.LocalPort; ProcessName = $r.ProcessName
        ProcessPath = $r.ProcessPath; ServiceNames = $r.ServiceNames; FirstSeen = $r.FirstSeen; LastSeen = $r.LastSeen
    }
}
$prevInfo = @(Import-Existing $infoFile)
$prevSamples = 0; $firstStart = $null
if ($prevInfo.Count -gt 0) {
    $prevSamples = [int]$prevInfo[0].Samples
    $firstStart = $prevInfo[0].CollectionStart
}

$start = Get-Date
$end = $start.AddMinutes($DurationMinutes)
$samples = 0
Write-Host ("[{0}] AppDepend collector {1} on {2}: sampling every {3}s until {4}" -f (Format-Time $start), $CollectorVersion, $hostName, $IntervalSeconds, (Format-Time $end))

# ---------------------------------------------------------------- sampling loop

$procMap = Get-ProcessServiceMap
$procMapAge = 0
do {
    $now = Get-Date; $nowText = Format-Time $now
    # Refresh the PID map every 4 samples, or whenever we meet an unknown PID.
    if ($procMapAge -ge 4) { $procMap = Get-ProcessServiceMap; $procMapAge = 0 }
    $procMapAge++

    $snapshot = Get-TcpSnapshot
    if (@($snapshot | Where-Object { $_.OwningProcess -gt 4 -and -not $procMap.ContainsKey($_.OwningProcess) }).Count -gt 0) {
        $procMap = Get-ProcessServiceMap; $procMapAge = 0
    }

    # 1. Listening ports in this snapshot (needed to classify direction).
    $listenPorts = @{}
    foreach ($c in $snapshot) {
        if ($c.State -ne 'Listen') { continue }
        $listenPorts[[int]$c.LocalPort] = $true
        $laddr = ConvertTo-PlainIPv4 $c.LocalAddress
        if (-not $IncludeLoopback -and (Test-IsLoopback $laddr)) { continue }
        $k = "$laddr|$($c.LocalPort)"
        $pi = $procMap[[int]$c.OwningProcess]
        if (-not $listeners.ContainsKey($k)) {
            $listeners[$k] = @{
                LocalAddress = $laddr; LocalPort = [int]$c.LocalPort
                ProcessName = $(if ($pi) { $pi.Name } else { "PID$($c.OwningProcess)" })
                ProcessPath = $(if ($pi) { $pi.Path } else { '' })
                ServiceNames = $(if ($pi) { ($pi.Services -join ';') } else { '' })
                FirstSeen = $nowText; LastSeen = $nowText
            }
        } else { $listeners[$k].LastSeen = $nowText }
    }
    # Previously-seen listeners also count (a service may be restarting right now).
    foreach ($l in $listeners.Values) { $listenPorts[[int]$l.LocalPort] = $true }

    # 2. Connections, aggregated by direction / remote IP / service port / process.
    $concurrent = @{}
    foreach ($c in $snapshot) {
        if ($c.State -eq 'Listen' -or $c.State -eq 'Bound') { continue }
        $raddr = ConvertTo-PlainIPv4 $c.RemoteAddress
        $laddr = ConvertTo-PlainIPv4 $c.LocalAddress
        if (Test-IsUnspecified $raddr) { continue }
        if (-not $IncludeLoopback -and ((Test-IsLoopback $raddr) -or (Test-IsLoopback $laddr))) { continue }
        if ($localIPs -contains $raddr) { continue }   # host talking to itself via its own IP

        if ($listenPorts.ContainsKey([int]$c.LocalPort)) { $dir = 'Inbound';  $port = [int]$c.LocalPort }
        else                                             { $dir = 'Outbound'; $port = [int]$c.RemotePort }

        $pi = $procMap[[int]$c.OwningProcess]
        if ($c.State -eq 'TimeWait' -or [int]$c.OwningProcess -eq 0) { $pname = '(closed)'; $ppath = ''; $svc = '' }
        elseif ($pi) { $pname = $pi.Name; $ppath = $pi.Path; $svc = ($pi.Services -join ';') }
        else { $pname = "PID$($c.OwningProcess)"; $ppath = ''; $svc = '' }

        # For inbound, attribute the owning listener's process to TIME_WAIT rows.
        if ($pname -eq '(closed)' -and $dir -eq 'Inbound') {
            foreach ($l in $listeners.Values) {
                if ([int]$l.LocalPort -eq $port) { $pname = $l.ProcessName; $ppath = $l.ProcessPath; $svc = $l.ServiceNames; break }
            }
        }

        $key = '{0}|{1}|{2}|{3}' -f $dir, $raddr, $port, $pname
        if (-not $concurrent.ContainsKey($key)) { $concurrent[$key] = 0 }
        $concurrent[$key]++

        if (-not $conns.ContainsKey($key)) {
            $conns[$key] = @{
                Direction = $dir; RemoteAddress = $raddr; Port = $port
                ProcessName = $pname; ProcessPath = $ppath; ServiceNames = $svc
                States = $c.State; FirstSeen = $nowText; LastSeen = $nowText
                SampleCount = 0; MaxConcurrent = 0
            }
        }
        $e = $conns[$key]
        $e.LastSeen = $nowText
        if ((";" + $e.States + ";") -notlike "*;$($c.State);*") { $e.States = $e.States + ';' + $c.State }
        if (-not $e.ProcessPath -and $ppath) { $e.ProcessPath = $ppath }
        if (-not $e.ServiceNames -and $svc) { $e.ServiceNames = $svc }
    }
    foreach ($k in $concurrent.Keys) {
        $conns[$k].SampleCount++
        if ($concurrent[$k] -gt $conns[$k].MaxConcurrent) { $conns[$k].MaxConcurrent = $concurrent[$k] }
    }
    $samples++

    if ((Get-Date) -lt $end) { Start-Sleep -Seconds $IntervalSeconds }
} while ((Get-Date) -lt $end)

# ---------------------------------------------------------------- output

$connCols = 'Hostname','Direction','RemoteAddress','Port','ProcessName','ProcessPath','ServiceNames','States','FirstSeen','LastSeen','SampleCount','MaxConcurrent'
$conns.Values | ForEach-Object {
    $o = New-Object PSObject -Property $_
    $o | Add-Member -NotePropertyName Hostname -NotePropertyValue $hostName -Force
    $o
} | Sort-Object Direction, Port, RemoteAddress | Select-Object $connCols |
    Export-Csv -Path $connFile -NoTypeInformation -Encoding UTF8

$listeners.Values | ForEach-Object {
    $o = New-Object PSObject -Property $_
    $o | Add-Member -NotePropertyName Hostname -NotePropertyValue $hostName -Force
    $o
} | Sort-Object LocalPort | Select-Object Hostname, LocalAddress, LocalPort, ProcessName, ProcessPath, ServiceNames, FirstSeen, LastSeen |
    Export-Csv -Path $listFile -NoTypeInformation -Encoding UTF8

# Running services that are not part of Windows: these usually identify the application.
try {
    Get-WmiData Win32_Service "State='Running'" | Where-Object {
        $_.PathName -and $_.PathName -notmatch '\\Windows\\(system32|SysWOW64)\\(svchost|lsass|services|spoolsv|wininit|winlogon|dllhost|msdtc|vds|wbem)'
    } | ForEach-Object {
        New-Object PSObject -Property ([ordered]@{
            Hostname = $hostName; Name = $_.Name; DisplayName = $_.DisplayName
            StartMode = $_.StartMode; StartName = $_.StartName; PathName = $_.PathName; ProcessId = $_.ProcessId
        })
    } | Export-Csv -Path $svcFile -NoTypeInformation -Encoding UTF8
} catch { Write-Warning "Could not enumerate services: $($_.Exception.Message)" }

$finish = Get-Date
New-Object PSObject -Property ([ordered]@{
    Hostname         = $hostName
    FQDN             = $fqdn
    Domain           = $domain
    OS               = $os
    OSVersion        = $osVersion
    PSVersion        = $PSVersionTable.PSVersion.ToString()
    IPAddresses      = ($localIPs -join ';')
    CollectionStart  = $(if ($firstStart) { $firstStart } else { Format-Time $start })
    CollectionEnd    = Format-Time $finish
    Samples          = $prevSamples + $samples
    IntervalSeconds  = $IntervalSeconds
    CollectorVersion = $CollectorVersion
    Method           = $(if ($script:UseNetTcpCmdlet) { 'Get-NetTCPConnection' } else { 'netstat' })
}) | Export-Csv -Path $infoFile -NoTypeInformation -Encoding UTF8

Write-Host ("[{0}] Done. {1} samples this run, {2} flows, {3} listeners -> {4}" -f (Format-Time $finish), $samples, $conns.Count, $listeners.Count, $OutputPath)
