# Backend: VM Dependency Mapper & Migration Wave Planner (Phase 1)

FastAPI + SQLAlchemy 2 + Alembic. PostgreSQL is the target database. SQLite works for local
development. Phase 1 scope: **inventory CSV import and validation**. See `../docs/mvp/PLAN.md`.

> **No authentication yet.** Bind to `127.0.0.1` only. Do not deploy to a shared network before Phase 2 adds auth and roles.

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

uvicorn app.api.asgi:app --host 127.0.0.1 --port 8000
# http://127.0.0.1:8000/docs  (OpenAPI UI)
curl -F file=@../sample_data/inventory_vcenter.csv "http://127.0.0.1:8000/api/imports/inventory?commit=false"
```

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | liveness + DB check |
| `POST /api/imports/inventory?commit=&allow_partial=&force=&encoding=` | preview (default) or commit an inventory CSV |
| `GET /api/imports`, `GET /api/imports/{id}` | batch history; batch with all row issues |
| `GET /api/vms?search=&limit=&offset=` | inventory search (name, application, owner, IP) |

## Configuration (`VDM_*` environment variables or `.env`)

| Variable | Default | Meaning |
|---|---|---|
| `VDM_DATABASE_URL` | `sqlite:///./data/vdm.db` | e.g. `postgresql+psycopg://vdm:<password>@host:5432/vdm` |
| `VDM_MAX_UPLOAD_MB` | 50 | upload size limit |
| `VDM_MAX_INVENTORY_ROWS` | 20000 | row limit per inventory file |
| `VDM_DEFAULT_ACTOR` | `local-user` | audit actor until authentication exists |
| `VDM_CRITICALITY_VALUES` | `["critical","high","medium","low"]` | other values raise a warning |

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
