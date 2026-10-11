# Inventory CSV schema v1 (`inventory-csv-v1`)

One row per VM. UTF-8 (BOM allowed), comma, semicolon or tab delimited (auto-detected), with a header
row. Header matching **ignores case, spaces and punctuation**, and common vCenter/RVTools vInfo
headers are accepted as aliases, so an RVTools vInfo CSV can be imported unchanged.

| Field | Required | Accepted headers (aliases) | Normalisation / validation |
|---|---|---|---|
| `vm_name` | **yes** | vm_name, VM, VM Name, Name | Trimmed. Empty → **error** |
| `vm_uuid` | strongly recommended | vm_uuid, VM UUID, Instance UUID, VI SDK UUID, SMBIOS UUID, UUID | Accepts 8-4-4-4-12, 32 hex, or VMware BIOS form `42 1f ... -...`. Stored lower-case dashed. Invalid → **error** |
| `vcenter` | recommended | vcenter, vCenter, vCenter Server, VI SDK Server | Scopes the identity (the same UUID can exist in two vCenters) |
| `moref` | no | moref, VM ID, MoRef, MOID | e.g. `vm-1234` |
| `dns_name` | no | dns_name, DNS Name, FQDN, Hostname | |
| `guest_os` | no | guest_os, OS according to the VMware Tools, OS according to the configuration file, Guest OS, OS | |
| `power_state` | no | power_state, Powerstate, Power State | `poweredOn`/`poweredOff`/`suspended` (also on/off/running/stopped). Other values → warning |
| `template` | no | template, Template | `true`/`yes`/`1` → row skipped (info) |
| `cluster`, `datacenter` | no | Cluster, Datacenter | |
| `environment` | no | environment, Env | e.g. production, uat |
| `application` | no | application, App, Application Name | |
| `owner` | no | owner, Application Owner, App Owner | |
| `criticality` | no | criticality, Business Criticality | Lower-cased. Not in `VDM_CRITICALITY_VALUES` → warning (kept) |
| `tier` | no | tier, Tier, Role | e.g. web, app, db, shared |
| `ip_addresses` | no | ip_addresses, IP Addresses, Primary IP Address, IPv4 Address, IPv6 Address, IP Address, IP | Several values separated by `;` `,` or space. Several columns are merged. Invalid → warning (ignored); loopback/link-local dropped; IPv4-mapped IPv6 → IPv4 |
| `mac_addresses` | no | mac_addresses, MAC Addresses, MAC Address, MAC | Normalised to `aa:bb:cc:dd:ee:ff`. Invalid → warning |
| `networks` | no | networks, Network, Networks, Port Group, Network #1..#4 | Several values separated by `;` or `\|` |

Unmapped columns are kept in `raw_record` (reported once as info).

## Identity

* With `vm_uuid`: `uuid:<vcenter>:<vm_uuid>`. Stable across renames.
* Without `vm_uuid`: `name:<vcenter>:<lower(vm_name)>` (info issue on every such row). **A rename
  creates a new record.** Supply UUIDs for production use.
* Two rows with the same identity in one file → **error on both rows**.
* The same name with different identities → warning (ambiguous name lookups).
* The same IP on several VMs → warning (VIP, cluster IP, or stale data). Flows to that IP will be ambiguous.
* A new identity whose name already exists in the database under another identity → warning
  `possible_duplicate` (typically a UUID added in a later export, or a differing vCenter column).

## Re-import (merge) rules

1. A **column absent from the file never changes stored values.** A vCenter export without
   `owner` does not erase owners imported earlier from the CMDB file.
2. **Blank cells never clear a stored value.** (Clearing will be a reviewed manual edit in a later phase.)
3. Interfaces are replaced when the file has interface columns and the row has values. Parts the
   file has no column for (e.g. MACs in RVTools vInfo) are carried over. If an import would
   **remove an IP**, a warning `ips_removed` is raised. This is expected when an IP was re-assigned and wrong when the file only lists a primary IP.
4. VMs missing from a later file are **not deleted**. `last_import_batch_id` shows when each was last seen.

## Commit policy (same for every importer, see `import-workflow.md`)

* Preview is the default and writes nothing. It returns every issue and the rejected rows.
* Any **error** → commit refused (HTTP 409). Importing only the valid rows needs `allow_partial=true`
  **and** `partial_reason` (≥ 10 characters). The decision, reason and actor are stored on the batch
  and in the audit log, and the rejected rows are stored verbatim. An administrator can disable partial
  imports entirely (`VDM_ALLOW_PARTIAL_IMPORTS=false`).
* More than 50 % invalid rows (`VDM_MAX_INVALID_RECORD_RATIO`) → the file is rejected as a whole.
* A file with the **same SHA-256** as an earlier batch → refused unless `force=true`.
* Limits: `VDM_MAX_UPLOAD_MB` (default 50), `VDM_MAX_INVENTORY_ROWS` (default 20,000). Only
  `.csv`/`.txt`. NUL bytes (an `.xlsx` renamed to `.csv`) are rejected.
* Non-UTF-8 → rejected with guidance. Pass `encoding=cp874` (Thai Windows) or another encoding explicitly.

## Example

```csv
vm_name,vm_uuid,vcenter,guest_os,environment,application,owner,criticality,tier,ip_addresses,mac_addresses,networks
HR-SQL01,6b1f...-...,vcsa01.corp.example,Microsoft Windows Server 2016 (64-bit),production,HR Portal,hr-owner@corp.example,high,db,10.20.3.11;10.20.3.50,00:50:56:00:00:07,PG-HR-DB
```

Full samples are in `sample_data/` (regenerate with `python -m app.cli sample-data -o ../sample_data`).
