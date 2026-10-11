"""Headless operations (no network access; works only on local files and the configured DB):
    python -m app.cli db-upgrade
    python -m app.cli sample-data -o ../sample_data
    python -m app.cli parsers
    python -m app.cli import-inventory FILE [--commit] [--allow-partial --partial-reason TEXT] [--force]
                                            [--encoding cp874] [--error-report report.csv]
    python -m app.cli import-telemetry FILE --parser NAME [--timezone Asia/Bangkok] [--window-start ISO --window-end ISO]
                                            [--commit] [--allow-partial --partial-reason TEXT] [--force] [--error-report report.csv]
    python -m app.cli resolve BATCH_ID
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path

from .config import get_settings


def db_upgrade(url: str | None = None) -> None:
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    if url:
        cfg.attributes["database_url"] = url
    command.upgrade(cfg, "head")


def _print_issues(issues) -> None:
    for issue in issues:
        where = f"row {issue.row_number}" if issue.row_number else "file"
        print(f"  {issue.severity.upper():<7} {where:<9} {issue.code:<24} {issue.message}"
              + (f"  [{issue.raw_value}]" if issue.raw_value else ""))


def _write_error_report(path: str, issues, rejected) -> None:
    from .security import spreadsheet_safe

    raw = {r.row_number: r.raw for r in rejected}
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["row_number", "severity", "code", "field", "message", "raw_value", "rejected_row"])
        for i in issues:
            w.writerow([spreadsheet_safe(v) for v in (i.row_number, i.severity, i.code, i.field, i.message, i.raw_value,
                                                      raw.get(i.row_number, ""))])
    print(f"Error report written to {path}")


def _commit_flags(p) -> None:
    p.add_argument("--commit", action="store_true", help="write to the database (default: validation preview only)")
    p.add_argument("--allow-partial", action="store_true", help="import only valid records (needs --partial-reason)")
    p.add_argument("--partial-reason", help="why importing only the valid records is acceptable (audited)")
    p.add_argument("--force", action="store_true", help="re-import a file identical to an earlier batch")
    p.add_argument("--encoding")
    p.add_argument("--error-report", help="write issues and rejected rows to this CSV")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("db-upgrade", help="apply database migrations")
    s = sub.add_parser("sample-data", help="write synthetic inventory and telemetry CSV files")
    s.add_argument("-o", "--out", default="sample_data")
    sub.add_parser("parsers", help="list supported telemetry source formats")
    i = sub.add_parser("import-inventory", help="validate (default) or commit an inventory CSV")
    i.add_argument("file")
    _commit_flags(i)
    t = sub.add_parser("import-telemetry", help="validate (default) or commit a telemetry file")
    t.add_argument("file")
    t.add_argument("--parser", required=True)
    t.add_argument("--timezone", help="IANA zone for timestamps without offset")
    t.add_argument("--window-start")
    t.add_argument("--window-end")
    _commit_flags(t)
    r = sub.add_parser("resolve", help="run endpoint resolution for a flow batch")
    r.add_argument("batch_id")
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
    if args.cmd == "parsers":
        from .telemetry.registry import list_parsers

        for cls in list_parsers():
            info = cls.info
            print(f"{info.name} {info.version} [{info.kind}]: {info.description}\n"
                  f"    required: {', '.join(info.required_fields)}\n    status: {info.validation_status}")
        return 0

    from .db import make_engine, make_session_factory
    from .importers.common import FileError
    from .services.policy import ImportRefused, audit_refusal

    session = make_session_factory(make_engine(settings.database_url))()
    try:
        if args.cmd == "resolve":
            from .services.resolution import ResolutionError, run_resolution

            try:
                summary = run_resolution(session, settings, args.batch_id, settings.default_actor)
            except ResolutionError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 2
            print(f"Resolved {summary['distinct_ips']} distinct IPs into {summary['mapping_rows']} mapping rows:")
            for k, n in sorted(summary["by_status_confidence"].items()):
                print(f"  {k:<22} {n}")
            return 0

        path = Path(args.file)
        if args.cmd == "import-inventory":
            from .importers.inventory import parse_inventory_csv
            from .services.inventory import commit_import, plan_import

            data = path.read_bytes()
            try:
                parsed = parse_inventory_csv(data, max_bytes=settings.max_upload_bytes, max_rows=settings.max_inventory_rows,
                                             encoding=args.encoding, criticality_values=settings.criticality_values,
                                             max_invalid_ratio=settings.max_invalid_record_ratio)
            except FileError as exc:
                print(f"FILE REJECTED ({exc.code}): {exc}", file=sys.stderr)
                return 2
            plan = plan_import(session, parsed, data)
            issues = parsed.issues + plan.extra_issues
            _print_issues(issues)
            print(f"{path.name}: {parsed.row_count} rows ({parsed.source_system}, {parsed.encoding}) -> "
                  f"{len(plan.new)} new, {len(plan.updated)} updated, {len(plan.unchanged)} unchanged, "
                  f"{parsed.rejected_rows} rejected, {parsed.count('error')} errors, "
                  f"{sum(1 for x in issues if x.severity == 'warning')} warnings")
            if args.error_report:
                _write_error_report(args.error_report, issues, parsed.rejected)
            sha, action = plan.sha256, "inventory.import"

            def do_commit():
                return commit_import(session, parsed, plan, settings=settings, file_name=path.name, data=data,
                                     actor=settings.default_actor, allow_partial=args.allow_partial,
                                     partial_reason=args.partial_reason, force=args.force)
        else:
            from zoneinfo import ZoneInfo

            from .services.telemetry import commit_telemetry, parse_telemetry
            from .telemetry.base import ParseContext

            ctx = ParseContext(timezone=ZoneInfo(args.timezone) if args.timezone else None,
                               window_start=datetime.fromisoformat(args.window_start) if args.window_start else None,
                               window_end=datetime.fromisoformat(args.window_end) if args.window_end else None,
                               max_rows=settings.max_telemetry_rows)
            try:
                with open(path, "rb") as fh:
                    result = parse_telemetry(fh, args.parser, ctx, settings, args.encoding)
            except FileError as exc:
                print(f"FILE REJECTED ({exc.code}): {exc}", file=sys.stderr)
                return 2
            _print_issues(result.log.issues())
            agg = f", {len(result.aggregator.groups)} aggregated conversations" if result.aggregator else ""
            print(f"{path.name}: {result.rows} records ({result.parser_name}, {result.encoding}) -> {result.accepted} valid, "
                  f"{len(result.rejected)} rejected, {result.errors} errors, {result.warnings} warnings{agg}")
            if args.error_report:
                _write_error_report(args.error_report, result.log.issues(), result.rejected)
            sha, action = result.sha256, ("telemetry" if result.kind == "flow" else "address") + ".import"

            def do_commit():
                return commit_telemetry(session, result, settings=settings, file_name=path.name,
                                        actor=settings.default_actor, allow_partial=args.allow_partial,
                                        partial_reason=args.partial_reason, force=args.force, timezone_name=args.timezone)

        if not args.commit:
            print("Validation preview only. Nothing was written. Add --commit to import.")
            return 0
        try:
            batch = do_commit()
        except ImportRefused as exc:
            session.rollback()
            audit_refusal(session, actor=settings.default_actor, action=action, file_name=path.name, sha256=sha, reason=exc)
            print(f"REFUSED ({exc.code}): {exc}", file=sys.stderr)
            return 3
        print(f"Committed as batch {batch.id} ({batch.status}).")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
