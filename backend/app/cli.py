"""Headless operations:
    python -m app.cli db-upgrade
    python -m app.cli sample-data -o ../sample_data
    python -m app.cli import-inventory FILE [--commit] [--allow-partial] [--force] [--encoding cp874]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import get_settings


def db_upgrade(url: str | None = None) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent.parent / "migrations"))
    if url:
        cfg.attributes["database_url"] = url
    command.upgrade(cfg, "head")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("db-upgrade", help="apply database migrations")
    s = sub.add_parser("sample-data", help="write synthetic inventory CSV files")
    s.add_argument("-o", "--out", default="sample_data")
    i = sub.add_parser("import-inventory", help="preview (default) or commit an inventory CSV")
    i.add_argument("file")
    i.add_argument("--commit", action="store_true")
    i.add_argument("--allow-partial", action="store_true")
    i.add_argument("--force", action="store_true")
    i.add_argument("--encoding")
    args = p.parse_args(argv)
    settings = get_settings()

    if args.cmd == "db-upgrade":
        db_upgrade()
        print("Database is at the latest revision.")
        return 0

    if args.cmd == "sample-data":
        from .sampledata import write_samples

        for path in write_samples(Path(args.out)):
            print(path)
        return 0

    from .db import make_engine, make_session_factory
    from .importers.inventory import InventoryFileError, parse_inventory_csv
    from .services.inventory import ImportRefused, audit_refusal, commit_import, plan_import

    path = Path(args.file)
    data = path.read_bytes()
    try:
        parsed = parse_inventory_csv(data, max_bytes=settings.max_upload_bytes, max_rows=settings.max_inventory_rows,
                                     encoding=args.encoding, criticality_values=settings.criticality_values)
    except InventoryFileError as exc:
        print(f"REJECTED ({exc.code}): {exc}", file=sys.stderr)
        return 2
    session = make_session_factory(make_engine(settings.database_url))()
    try:
        plan = plan_import(session, parsed, data)
        issues = parsed.issues + plan.extra_issues
        for issue in issues:
            where = f"row {issue.row_number}" if issue.row_number else "file"
            print(f"  {issue.severity.upper():<7} {where:<9} {issue.code:<20} {issue.message}"
                  + (f"  [{issue.raw_value}]" if issue.raw_value else ""))
        print(f"{path.name}: {parsed.row_count} rows ({parsed.source_system}, {parsed.encoding}) -> "
              f"{len(plan.new)} new, {len(plan.updated)} updated, {len(plan.unchanged)} unchanged, "
              f"{parsed.rejected_rows} rejected, {parsed.count('error')} errors, "
              f"{sum(1 for x in issues if x.severity == 'warning')} warnings")
        if plan.previous_batch_id:
            print(f"Note: this exact file was already imported as batch {plan.previous_batch_id}.")
        if not args.commit:
            print("Preview only. Nothing was written. Add --commit to import.")
            return 0
        try:
            batch = commit_import(session, parsed, plan, file_name=path.name, data=data, actor=settings.default_actor,
                                  allow_partial=args.allow_partial, force=args.force)
        except ImportRefused as exc:
            session.rollback()
            audit_refusal(session, actor=settings.default_actor, file_name=path.name, sha256=plan.sha256, reason=exc)
            print(f"REFUSED ({exc.code}): {exc}", file=sys.stderr)
            return 3
        print(f"Committed as batch {batch.id} ({batch.status}).")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
