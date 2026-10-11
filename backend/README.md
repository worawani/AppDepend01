# Backend: VM Dependency Mapper & Migration Wave Planner (Phases 1–2)

FastAPI + SQLAlchemy 2 + Alembic. PostgreSQL is the target database. SQLite works for local
development. Scope so far: inventory import, **telemetry parser interface (canonical formats only,
no vendor parsers)**, the shared validation workflow, and **endpoint resolution**. See `../docs/mvp/PLAN.md`.

> **No authentication yet.** Bind to `127.0.0.1` only. Do not deploy to a shared network before authentication and roles are added (next phase).

## Setup

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # edit VDM_DATABASE_URL; never commit .env
python -m app.cli db-upgrade    # apply migrations
```

## Use

```bash
python -m app.cli sample-data -o ../sample_data
python -m app.cli import-inventory ../sample_data/inventory_with_errors.csv          # preview: lists every issue, writes nothing
python -m app.cli import-inventory ../sample_data/inventory_vcenter.csv --commit
python -m app.cli import-inventory ../sample_data/inventory_rvtools_vinfo.csv --commit   # merge from a vCenter export

# Phase 2: DNS/DHCP evidence, flows, resolution (synthetic fixtures)
python -m app.cli parsers
python -m app.cli import-telemetry ../sample_data/address_records_canonical.csv --parser canonical-address-csv --commit
python -m app.cli import-telemetry ../sample_data/flows_with_errors.csv --parser canonical-flow-csv --error-report /tmp/errors.csv
python -m app.cli import-telemetry ../sample_data/flows_canonical.csv --parser canonical-flow-csv --commit
python -m app.cli resolve <flow batch id printed above>

uvicorn app.api.asgi:app --host 127.0.0.1 --port 8000
# http://127.0.0.1:8000/docs  (OpenAPI UI)
curl -F file=@../sample_data/inventory_vcenter.csv "http://127.0.0.1:8000/api/imports/inventory?commit=false"
```

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | liveness + DB check |
| `POST /api/imports/inventory?commit=&allow_partial=&partial_reason=&force=&encoding=` | preview (default) or commit an inventory CSV |
| `GET /api/imports`, `GET /api/imports/{id}` | batch history; batch with all row issues |
| `GET /api/vms?search=&limit=&offset=` | inventory search (name, application, owner, IP) |
| `GET /api/telemetry/parsers` | supported source formats and their validation status |
| `POST /api/imports/telemetry?parser=&commit=&allow_partial=&partial_reason=&force=&timezone=&window_start=&window_end=` | preview or commit flows / DNS-DHCP evidence |
| `GET /api/imports/{id}/rejected`, `GET /api/imports/{id}/error-report.csv` | rejected rows verbatim; full error report |
| `POST /api/resolution/{batch_id}/run` | resolve every endpoint of a flow batch (re-runnable, audited) |
| `GET /api/endpoint-mappings?batch_id=&status=&confidence=&ip=&needs_review=` | mappings with reason, evidence, candidates |
| `GET /api/endpoint-mappings/summary?batch_id=` | counts and % of flow endpoints resolved |

Partial imports need `allow_partial=true` **and** a `partial_reason`. See `../docs/mvp/import-workflow.md`.

## Configuration (`VDM_*` environment variables or `.env`)

| Variable | Default | Meaning |
|---|---|---|
| `VDM_DATABASE_URL` | `sqlite:///./data/vdm.db` | e.g. `postgresql+psycopg://vdm:<password>@host:5432/vdm` |
| `VDM_MAX_UPLOAD_MB` | 50 | upload size limit |
| `VDM_MAX_INVENTORY_ROWS` | 20000 | row limit per inventory file |
| `VDM_DEFAULT_ACTOR` | `local-user` | audit actor until authentication exists |
| `VDM_CRITICALITY_VALUES` | `["critical","high","medium","low"]` | other values raise a warning |
| `VDM_ALLOW_PARTIAL_IMPORTS` | `true` | `false` forbids partial imports |
| `VDM_PARTIAL_REASON_MIN_LENGTH` | 10 | |
| `VDM_MAX_INVALID_RECORD_RATIO` | 0.5 | above this the whole file is rejected |
| `VDM_MAX_REJECTED_ROWS_STORED` | 100000 | |
| `VDM_ISSUE_EXAMPLES_PER_CODE` | 100 | |
| `VDM_MAX_TELEMETRY_UPLOAD_MB` | 512 | |
| `VDM_MAX_TELEMETRY_ROWS` | 2000000 | ~0.6 KB RAM per distinct conversation-hour (measured) |
| `VDM_INVENTORY_STALENESS_DAYS` | 90 | inventory IP matches further than this from the snapshot become medium confidence |

## Tests

```bash
pytest                                   # SQLite
VDM_TEST_POSTGRES_URL=postgresql+psycopg://user@127.0.0.1:5432/vdm_test pytest   # + PostgreSQL (the DB is wiped!)
```

They include a model-vs-migration drift check, upgrade/downgrade, and the 1,000-VM import
acceptance test (reference §11).

## Changing the schema

Edit `app/models.py`, add a new hand-written revision under `migrations/versions/`, and run
the tests. `test_models_match_migrations` fails if the two disagree.
