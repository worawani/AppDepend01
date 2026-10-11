# VM Dependency Mapper & Migration Wave Planner: MVP plan

This document follows the reference *VM Dependency Mapper & Migration Wave Planner: Architecture
Recommendation and MVP Implementation Brief* (§13.1). It covers the repository review, the
proposed structure, key decisions, the schema, the input schemas, and the Phase 1 plan and tests.

**Status:** Phase 1 (first increment) implemented. **Waiting for review before Phase 2.**

---

## 0. Repository review: what already exists and how it fits

The repository already contains a tool built before the reference was available:

| Existing part | Fit against the reference | Decision |
|---|---|---|
| `collector/` PowerShell collector + Scheduled Task on every VM | **Violates §2.2 / §7**: "No agent deployment or scripts running on production Windows VMs" | Kept but **out of MVP scope**. Not used by the MVP. It can be a later, separately approved telemetry source because it is the only source that gives **process identity**. |
| `analyzer/` Python CLI (static HTML/Excel) | Useful logic (cross-wave detection, shared-service handling, unresolved endpoints, coverage), but no evidence model, no audit, no approvals, keyed by VM name | Kept as a reference implementation. Its **algorithms** are ported into `backend/` in Phases 2–3. It is not extended further. |
| Excel export in `analyzer/` | Was vulnerable to spreadsheet formula injection (§7) | **Fixed** (`safe_cell`) with a test. |

## 1. Proposed structure

```
backend/                 Python 3.11+ / FastAPI service  (Phase 1: implemented)
  app/
    config.py            settings from VDM_* env vars / .env (no secrets in code)
    db.py                engine + session factory (PostgreSQL; SQLite for local dev)
    models.py            SQLAlchemy 2.0 ORM, mirrors the migrations
    importers/inventory.py   inventory CSV parsing, normalisation, validation
    services/inventory.py    preview / commit / upsert / duplicate-import guard / audit
    api/                 FastAPI routers (health, imports, vms)
    security.py          spreadsheet-safe value escaping (used by all exports)
    sampledata.py        deterministic synthetic data generator
    cli.py               headless import + sample generation
  migrations/            Alembic, hand-written portable migrations
  tests/                 pytest (unit, API, migration, PostgreSQL when available)
frontend/                React + TypeScript + Cytoscape.js   (Phase 2)
deploy/                  docker-compose, nginx/TLS, backup scripts (Phase 4)
sample_data/             synthetic inventory files (generated)
docs/mvp/                plan, input schemas, decisions
collector/, analyzer/    pre-reference tool (see §0)
```

## 2. Key implementation decisions and assumptions

| # | Decision | Why |
|---|---|---|
| D1 | **PostgreSQL is the target; SQLite only for local dev and tests.** Migrations are hand-written with portable types and are tested on both | §3.2. Avoids a painful SQLite → PostgreSQL migration later |
| D2 | **Surrogate UUID primary keys** plus a unique `identity_key`: `uuid:<vcenter>:<vm_uuid>` when a VM UUID exists, otherwise `name:<vcenter>:<lower(name)>` | §8: the display name is not a stable key. Name-based identity is a fallback and is marked as such |
| D3 | VMs missing from a later import are **not deleted**. `last_import_batch_id` shows staleness | Deleting planning data on a partial export is dangerous |
| D4 | **Commit is all-or-nothing by default.** If any row has an error, commit is refused (HTTP 409) unless `allow_partial=true`. Preview never writes | Planning data must be consistent. The escape hatch is explicit and audited |
| D5 | An **identical file (same SHA-256) cannot be re-imported** unless `force=true` | §9 "prevent accidental duplicate imports" |
| D6 | Encoding: **UTF-8 (with/without BOM) only, strict.** A non-UTF-8 file is rejected with a clear message, or an explicit `encoding` (e.g. `cp874`) can be passed | Silent cp1252/cp874 guessing corrupts Thai text without warning |
| D7 | Raw values are kept (`raw_record` JSON per VM, `raw_value` per issue), and formula-like text is stored unchanged and **escaped on export** | §3.1 keep raw values; §7 spreadsheet safety |
| D8 | Phase 1 has **no authentication**. The API binds to `127.0.0.1` by default, and the actor comes from config. Auth/roles arrive in Phase 2 *before* any non-local deployment | Scope control. This is a stated limitation, not a design choice |
| D9 | Templates are skipped; IPv4/IPv6 are validated and loopback/link-local dropped; MACs are normalised to `aa:bb:cc:dd:ee:ff` | Normalisation per §3.1 |
| D10 | Telemetry: **aggregate on import** (per src/dst/proto/port/hour) and keep the raw file and batch metadata, rather than storing every session row forever | Firewall session logs for 1,000 VMs can reach tens of millions of rows per day; §3.2 sizing |

### Challenges to the reference (decisions you need to make)

1. **Firewall logs alone will miss most of the dependencies that matter.** Web → app → DB tiers
   usually sit in the same VLAN/port group, so that traffic never crosses a firewall. Physical-switch
   NetFlow also misses VM-to-VM traffic on the same ESXi host.
   **Recommendation:** enable **IPFIX on the vSphere Distributed Switch** (agentless, sees intra-host
   VM traffic, and is a configuration change with no install on VMs) or use NSX DFW logs where present. This needs a VDS
   (vSphere Enterprise Plus). If the estate runs standard vSwitches, this option does not exist
   and the coverage gap must be stated in every report.
2. **Flow data has no process identity.** TCP/445 could be a file share, AD, or a backup agent,
   and flows cannot tell them apart. Owner confirmation (§5.1) carries more weight because of this. The
   existing PowerShell collector closes this gap but needs a formal exception to §2.2.
3. **4–5 weeks for a multi-user web app** with SSO, audit, approvals, backup/restore and a graph UI
   is tight for one developer. The estimate in §10 holds only if security approval, sample data
   and the firewall format decision arrive in Week 1.
4. **Open decision blocking Phase 2:** which firewall/flow source and format: vendor
   (Palo Alto, FortiGate, Check Point, Cisco ASA/FTD), VDS IPFIX via which collector, and the retention period.

## 3. Database schema and migration strategy

Alembic, one revision per phase, hand-written for portability, and tested by:
(a) `upgrade head` on empty SQLite and PostgreSQL, (b) `downgrade base`, and (c) an autogenerate
comparison asserting the ORM models and migrations do not drift.

**Revision 0001 (Phase 1, implemented)**

| Table | Key fields |
|---|---|
| `import_batch` | id, source_type (`inventory`/`telemetry`), source_system, file_name, file_sha256, file_size, encoding, parser_version, schema_version, uploaded_by, imported_at, status, row/accepted/rejected/warning counts, observation_window_start/end (telemetry), summary JSON |
| `vm_inventory` | id, identity_key (unique), vcenter, vm_uuid, moref, name, dns_name, guest_os, power_state, cluster, datacenter, environment, application, owner, criticality, tier, first/last_import_batch_id, source_row_ref, raw_record JSON, created_at, updated_at |
| `vm_network_interface` | id, vm_id, ip, mac, network, source_batch_id, valid_from, valid_to |
| `import_issue` | id, batch_id, row_number, severity (error/warning/info), code, field, message, raw_value |
| `audit_event` | id, at, actor, action, entity_type, entity_id, outcome, details JSON (prior/new values) |

**Later revisions (planned):** 0002 `flow_observation` (aggregated), `endpoint_mapping`,
`dependency`. 0003 `migration_wave`, `wave_assignment`, `dependency_review`, users/roles.
Field lists follow reference §5.2 and §8.

## 4. Input schemas

* Inventory CSV v1: [`inventory-csv-schema.md`](inventory-csv-schema.md) (implemented, includes RVTools vInfo header aliases)
* Telemetry CSV v0: [`telemetry-schema-proposal.md`](telemetry-schema-proposal.md) (**draft**, waiting for the format decision)

## 5. Phase 1 plan (first increment): done

1. Scaffold: `backend/` package, pinned requirements, `.env.example`, settings.
2. Database: SQLAlchemy models, Alembic environment, revision 0001.
3. Inventory importer: header alias mapping, normalisation, row and file validation.
4. Import service: preview diff (new/updated/unchanged), commit, duplicate guard, interface
   replacement, possible-duplicate detection, audit event.
5. API: `GET /api/health`, `POST /api/imports/inventory`, `GET /api/imports`,
   `GET /api/imports/{id}`, `GET /api/vms`. Plus a CLI.
6. Synthetic data: web/app/DB tiers across applications, a file with deliberate errors, and an RVTools-style
   export. The generator scales to 1,000+ VMs.

## 6. Phase 1 test plan

| Area | Tests |
|---|---|
| Parsing | canonical + RVTools headers, required column missing, empty name, invalid UUID, duplicate UUID in file, duplicate names without UUID, invalid/loopback IPs, invalid MACs, shared IP across VMs, templates skipped, unknown criticality, formula-like values kept raw |
| Input safety | non-UTF-8 rejected, explicit encoding accepted, size limit, row limit, empty file, header only, delimiter detection (`,` `;` tab) |
| Commit | new → updated → unchanged on re-import, identical file blocked unless `force`, errors block commit unless `allow_partial`, interfaces replaced not duplicated, possible-duplicate warning on identifier change, audit event written, **1,000-VM import twice yields 1,000 records** |
| API | health, preview vs commit, 409 on errors, 413 oversize, 415 wrong type, batch history and issues, VM search/pagination |
| Migrations | upgrade/downgrade on SQLite, model-vs-migration drift check, the same on PostgreSQL when `VDM_TEST_POSTGRES_URL` is set |
| Export safety | `csv_safe` / `excel_safe` neutralise `= + - @ \t \r` |

## 7. Next phases (not started)

* **Phase 2:** telemetry import (one agreed format), endpoint resolver (IP + time-valid DNS/DHCP;
  ambiguous/unresolved kept), dependency aggregation with evidence, auth/roles, React UI
  (dependency table with evidence drill-down *before* the graph, then wave assignment and cross-wave warnings).
* **Phase 3:** Excel/CSV reports, review workflow (owner-confirmed, exceptions with approver),
  coverage metrics, security tests.
* **Phase 4:** on-prem deployment (Docker Compose if approved), TLS, backup/restore test, pilot
  against one application with known dependencies.
