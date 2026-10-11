from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from app.cli import db_upgrade
from app.db import make_engine
from app.models import Base
from app.security import spreadsheet_safe

TABLES = {"import_batch", "vm_inventory", "vm_network_interface", "import_issue", "audit_event", "alembic_version"}


def test_upgrade_creates_tables_and_is_idempotent(db_url):
    db_upgrade(db_url)   # already at head (fixture): running again is a no-op
    engine = make_engine(db_url)
    assert TABLES <= set(inspect(engine).get_table_names())
    engine.dispose()


def test_models_match_migrations(db_url):
    """Fails when someone edits models.py without writing a migration (or vice versa)."""
    engine = make_engine(db_url)
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(ctx, Base.metadata)
    engine.dispose()
    assert diff == [], diff


def test_downgrade_to_base(db_url):
    from alembic import command
    from alembic.config import Config
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["database_url"] = db_url
    command.downgrade(cfg, "base")
    engine = make_engine(db_url)
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    engine.dispose()
    command.upgrade(cfg, "head")


def test_spreadsheet_safe():
    for bad in ("=1+1", "+1", "-1+cmd", "@SUM(A1)", "\tx", "\rx", '=HYPERLINK("http://x")'):
        assert spreadsheet_safe(bad) == "'" + bad
    for ok in ("HR-WEB01", "10.0.0.1", "", "a=b"):
        assert spreadsheet_safe(ok) == ok
    assert spreadsheet_safe(-5) == -5 and spreadsheet_safe(None) is None
