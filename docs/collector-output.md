# Collector output format

Each host writes four UTF-8 CSV files to the output folder. With `-Append`, rows are merged
across runs by key (counts summed, first/last seen extended).

## `<HOST>_connections.csv`: one row per aggregated flow

| Column | Meaning |
|---|---|
| Hostname | `%COMPUTERNAME%` of the collecting host |
| Direction | `Inbound` (the remote connected to a local listener) or `Outbound` |
| RemoteAddress | Peer IP (IPv4-mapped IPv6 normalised to IPv4) |
| Port | **Service port**: the local listening port for Inbound, the remote port for Outbound. Ephemeral ports are dropped |
| ProcessName / ProcessPath | Owning process. `(closed)` = seen only in TIME_WAIT on an outbound flow (process already gone) |
| ServiceNames | Windows services hosted in that process (`;`-separated), useful for svchost |
| States | TCP states observed (`Established;TimeWait;SynSent`...) |
| FirstSeen / LastSeen | Local time, ISO 8601 |
| SampleCount | Number of samples in which the flow was present. Divide by `Samples` in hostinfo to get persistence |
| MaxConcurrent | Highest number of simultaneous connections seen in one sample |

Key: `Direction | RemoteAddress | Port | ProcessName`.

## `<HOST>_listeners.csv`

`Hostname, LocalAddress, LocalPort, ProcessName, ProcessPath, ServiceNames, FirstSeen, LastSeen`.
These are TCP listeners (loopback excluded unless `-IncludeLoopback`).

## `<HOST>_services.csv`

The running services that are not core Windows: `Hostname, Name, DisplayName, StartMode, StartName, PathName, ProcessId`.
`StartName` shows service accounts, which are worth checking for AD dependencies in OCI.

## `<HOST>_hostinfo.csv`

`Hostname, FQDN, Domain, OS, OSVersion, PSVersion, IPAddresses (;-separated), CollectionStart,
CollectionEnd, Samples, IntervalSeconds, CollectorVersion, Method (Get-NetTCPConnection|netstat)`.

The analyzer matches a host to an inventory VM by VM name, then the DNS short name, then IP overlap,
so a Windows hostname that differs from the vSphere VM name is handled.
