from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.cli import db_upgrade
from app.config import Settings
from app.db import make_engine, make_session_factory


def _urls():
    yield "sqlite"
    if os.environ.get("VDM_TEST_POSTGRES_URL"):
        yield "postgresql"


@pytest.fixture(params=list(_urls()))
def db_url(request, tmp_path):
    """Fresh, migrated database per test: SQLite always, PostgreSQL too when VDM_TEST_POSTGRES_URL is set."""
    if request.param == "sqlite":
        url = f"sqlite:///{tmp_path / 'test.db'}"
    else:
        from sqlalchemy import text

        url = os.environ["VDM_TEST_POSTGRES_URL"]
        eng = make_engine(url)
        with eng.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
        eng.dispose()
    db_upgrade(url)
    return url


@pytest.fixture
def settings(db_url):
    return Settings(database_url=db_url, max_upload_mb=1, max_inventory_rows=5000, default_actor="tester")


@pytest.fixture
def session(settings):
    engine = make_engine(settings.database_url)
    s = make_session_factory(engine)()
    yield s
    s.close()
    engine.dispose()


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c
    app.state.engine.dispose()
