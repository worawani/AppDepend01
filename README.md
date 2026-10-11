# VM Dependency Mapper & Migration Wave Planner (vSphere → AIS Cloud / OCI Alloy)

This repository has two parts:

| Part | Status | Use it for |
|---|---|---|
| **[`backend/`](backend/): the MVP** that follows the *Architecture Recommendation & MVP Implementation Brief*: agentless, evidence-backed, PostgreSQL, FastAPI | **Phases 1–2 done**: inventory import, telemetry parser interface (canonical formats, synthetic-only), validation workflow, endpoint resolution. Vendor parser waits for the confirmed source and a sanitized sample | The supported path. Plan and status: [`docs/mvp/PLAN.md`](docs/mvp/PLAN.md) |
| **`collector/` + `analyzer/`: the earlier AppDepend tool** (below) | Works, but **outside MVP scope**: its collector runs a script on every VM, which the brief excludes (§2.2) | A pilot or second opinion where a change exception allows a script on VMs. It is the only source with *process identity*. Its algorithms are being ported into `backend/` |

---

# AppDepend (pre-MVP tool): application dependency mapping for vSphere → OCI migration waves

AppDepend finds out **which servers talk to which** before you pick the VMs for a migration
wave, then **checks a wave plan** against that data. It is built for Windows Server
2012 – 2025 VMs on vSphere.

```
 ┌──────────────── each Windows VM ────────────────┐     ┌──────────── your laptop / jump host ────────────┐
 │ Collect-AppDependency.ps1  (PowerShell 3.0+)    │     │ appdepend analyze / check  (Python 3.9+)        │
 │  samples TCP connections every 15 s for weeks   │ ──► │  + RVTools inventory  + wave plan               │
 │  → <HOST>_connections/listeners/services.csv    │     │  → HTML report (graph), Excel workbook, JSON    │
 └─────────────────────────────────────────────────┘     └─────────────────────────────────────────────────┘
   deployed by Invoke-RemoteCollection.ps1 (WinRM) or Invoke-VMToolsCollection.ps1 (vCenter / VMware Tools)
```

## What you get

| Output | Answers |
|---|---|
| **Wave Summary** (RED/AMBER/GREEN) | Is this wave safe to cut over? |
| **Cross-Wave Deps** | Which app flows become on-prem ↔ OCI traffic, and for how long? |
| **Move Groups** | Which VMs must move together, which groups my plan splits, and which VM to re-wave |
| **Unknown Endpoints** | Which IPs are not in vSphere (physical boxes, appliances, VIPs, internet) and need identifying |
| **Hubs** | Which shared servers (central SQL, file server) glue everything together |
| **VM Coverage** | Which VMs have no data or too little (blind spots) |
| **Firewall Flows** | The flows per wave: source, destination, port, intra-OCI vs. hybrid vs. internet. Input for OCI NSGs / Security Lists |
| **check** report | "If I put these VMs in Wave 4, what breaks, and what else do I need to bring?" |

## Quick start (demo data)

```bash
cd analyzer
pip install .                      # needs only openpyxl
appdepend sample -o ../samples     # synthetic 17-VM estate with planted mistakes
appdepend analyze -d ../samples/collected -i ../samples/inventory.csv -w ../samples/waves.csv \
                  -k ../samples/known-endpoints.csv -c ../samples/config.json -o report
# open report/dependency-report.html
appdepend check   -d ../samples/collected -i ../samples/inventory.csv -w ../samples/waves.csv \
                  -k ../samples/known-endpoints.csv -c ../samples/config.json --wave "Wave 2" -o report
```

The demo correctly reports that **HR-SQL01 is in Wave 3 while its app server is in Wave 2**,
that RPT01 reads databases from later waves, that 10.50.1.20 (IBM MQ) is unidentified,
that LEGACY01 has no data, and that `erp-app02_vm` is the VM whose Windows hostname is ERP-APP02.

No install is needed either: `python -m appdepend ...` from the `analyzer` folder works.

## Real-world runbook

### 1. Collect (2–4 weeks, including a month-end)

The collector is read-only and installs no software, but it **is not agentless**: it runs a
PowerShell script from a Scheduled Task on every VM, which needs change approval. It uses
`Get-NetTCPConnection`, falling back to `netstat -ano`, so it runs on Windows Server 2012 RTM
(PowerShell 3.0) through 2025. CPU cost is one TCP table read every 15 s.

**Via WinRM** (from a jump host, as a domain account that is local admin on the targets):
```powershell
$cred = Get-Credential CORP\svc-migration
.\collector\Invoke-RemoteCollection.ps1 -Mode Deploy  -ComputerListFile wave-candidates.txt -Credential $cred
.\collector\Invoke-RemoteCollection.ps1 -Mode Status  -ComputerListFile wave-candidates.txt -Credential $cred
.\collector\Invoke-RemoteCollection.ps1 -Mode Collect -ComputerListFile wave-candidates.txt -Credential $cred -LocalPath D:\AppDepend\collected
.\collector\Invoke-RemoteCollection.ps1 -Mode Remove  -ComputerListFile wave-candidates.txt -Credential $cred -PurgeData   # when done
```

**Via vCenter / VMware Tools** (DMZ or firewalled VMs, no WinRM needed; requires PowerCLI and
the `VirtualMachine.GuestOperations.*` privileges):
```powershell
Connect-VIServer vcsa01.corp.local
$guest = Get-Credential
.\collector\Invoke-VMToolsCollection.ps1 -Mode Deploy  -VMName (Get-Content wave-candidates.txt) -GuestCredential $guest
.\collector\Invoke-VMToolsCollection.ps1 -Mode Collect -VMName (Get-Content wave-candidates.txt) -GuestCredential $guest -LocalPath D:\AppDepend\collected
```

**Manually** on a single server: `.\Collect-AppDependency.ps1 -OutputPath C:\AppDepend\out -DurationMinutes 60`.

Deploy registers a SYSTEM Scheduled Task that runs 58 minutes of every hour with `-Append`,
so the CSVs on each server accumulate. `Collect` can be run any time to take a snapshot.

### 2. Inventory

Export **RVTools** and pass the `.xlsx` directly (`-i RVTools_export_all.xlsx`): the `vInfo` and
`vNetwork` sheets are read automatically, and templates are skipped. Any CSV with a VM name
column (and optionally IPs, OS, Application, Owner, Role, Wave) also works, and `-i` can be repeated.
Put `Role=shared` on shared-service VMs (AD, DNS, backup, monitoring, central file servers).

### 3. Wave plan

`waves.csv` with columns `VM,Wave` (optional `Date`, `Application`). Wave names sort naturally
(`Wave 2` < `Wave 10`). VMs without a wave are treated as *not yet planned / staying on-prem*.

### 4. Known endpoints

Each unidentified IP the report lists goes into `known-endpoints.csv` (`CIDR,Label,Category,Note`;
category is `app`, `infra`, `admin` or `external`). Typical entries: physical DB clusters, AS/400,
F5 SNAT pools, Exchange relays, NAS heads, partner networks. Re-run, and they appear labelled.

### 5. Iterate

```bash
appdepend analyze -d collected -i RVTools.xlsx -w waves.csv -k known-endpoints.csv -c config.json -o report
appdepend check   ... --wave "Wave 4"                 # validate one wave
appdepend check   ... --vms APP01,APP02,SQL07         # build a wave from candidates
appdepend check   ... --vms-file candidates.txt --name wave4-draft
```

The usual loop is: mark hubs as shared → re-run → fix split move groups → identify unknown IPs → re-run.

## How to read the results (and where people get it wrong)

* **"No dependencies" ≠ "no data".** A VM with no collector data is a blind spot. Coverage and
  the wave status call this out, and a wave containing one is RED.
* **Shared services wreck naive grouping.** Every Windows VM talks to AD/DNS/AV/backup. Those
  ports (53, 88, 389, 445-to-DCs, ...) and VMs marked shared are reported as `infra`, not used for
  grouping. Plan them as **Wave 0** (AD DC + DNS in OCI, jump host, monitoring, backup) or keep
  them reachable over FastConnect.
* **One giant move group means a hub is not marked shared**: a central SQL instance, a file
  server, a reporting server. See the **Hubs** sheet. Marking it shared is a planning decision,
  not cosmetics: you are accepting hybrid traffic to it during the migration.
* **Not every link must bind.** `--group-min-persistence 5` (or `group_min_persistence_pct`)
  ignores links present in < 5 % of samples *for grouping only*, e.g. a nightly report pull that
  tolerates FastConnect latency. Those links still appear in Cross-Wave Deps and Firewall Flows.
* **Latency sensitivity** is per port: SQL/Oracle/SMB/RPC = High, HTTP = Medium, SMTP/syslog = Low.
  A High-sensitivity link split across waves usually means a slow application or broken
  transactions during the hybrid period. Measure your FastConnect RTT and test.
* **Failed-only flows** (SYN_SENT, never established) usually mean stale config pointing at a
  decommissioned server. Clean them up, don't migrate them.

## Known limitations

Be explicit about these with the migration team:

| Limitation | Mitigation |
|---|---|
| **TCP only.** Windows does not record a remote peer for UDP sockets (DNS, syslog, SNMP, RADIUS, some licensing / VoIP) | Ask app owners; use NSX / vRNI flow data for UDP |
| **Sampling.** A connection that opens and closes within one interval can be missed | The closing side keeps TIME_WAIT for ~2 min, which the collector records, so most short connections are still caught. Keep the 15 s interval and run near-continuously |
| **Rare jobs** (quarterly, year-end, DR tests) won't appear in a 3-week window | Interview app owners for those; read Scheduled Tasks and SQL Agent jobs |
| **Windows only.** Linux, physical servers and appliances are not collected | They still appear as peers (seen from the Windows side) as unknown IPs; label them in known-endpoints |
| **Load balancers / NAT** hide the real client (you see the F5 SNAT IP) | Map SNAT pools in known-endpoints; take VIP→pool membership from the F5 config |
| **Duplicate IPs** (VIPs, cluster IPs, stale RVTools data) | Reported in Warnings; collector-reported IPs win over inventory |

If you already have **VMware Aria Operations for Networks (vRNI)** or NSX flow data, use it as well:
it sees all OSes and UDP at the network layer. AppDepend adds the process/service names that
network flows cannot provide.

## Repository layout

```
backend/     MVP service (FastAPI, SQLAlchemy, Alembic): inventory import, Phase 1
sample_data/ synthetic inventory CSVs for the MVP
docs/mvp/    MVP plan, inventory CSV schema, telemetry schema proposal
collector/   pre-MVP: PowerShell collector + WinRM and VMware Tools deployment
analyzer/    pre-MVP: Python package `appdepend` (CLI, analysis, Excel/HTML reports) + tests
samples/     pre-MVP demo dataset, example config.json
docs/        collector output format
```

Tests: `cd analyzer && python -m unittest discover -s tests`

The HTML report embeds [vis-network](https://github.com/visjs/vis-network) 9.1.9 (Apache-2.0 / MIT,
see `analyzer/appdepend/vendor/`), so it works on offline jump hosts.
