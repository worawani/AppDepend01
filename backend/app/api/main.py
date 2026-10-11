"""FastAPI application. No authentication yet: bind to localhost only
(docs/mvp/PLAN.md, decision D8)."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from datetime import datetime
from typing import Annotated
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from .. import __version__
from ..config import Settings, get_settings
from ..db import make_engine, make_session_factory
from ..importers.common import FileError
from ..importers.inventory import parse_inventory_csv
from ..models import EndpointMapping, ImportBatch, ImportIssue, ImportRejectedRow, VmInventory, VmNetworkInterface
from ..security import spreadsheet_safe
from ..services.inventory import commit_import, plan_import
from ..services.policy import ImportRefused, audit_refusal, previous_batch
from ..services.resolution import ResolutionError, run_resolution
from ..services.telemetry import commit_telemetry, parse_telemetry
from ..telemetry.base import ParseContext
from ..telemetry.registry import get_parser, list_parsers
from .schemas import (BatchDetail, BatchOut, EndpointMappingOut, EndpointMappingPage, InventoryImportResult, IssueCount,
                      IssueOut, ParserOut, RejectedRowOut, TelemetryImportResult, VmPage)

ALLOWED_EXTENSIONS = (".csv", ".txt")
REJECTED_PREVIEW = 50


def get_session(request: Request) -> Iterator[Session]:
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


SessionDep = Annotated[Session, Depends(get_session)]


def _check_name(name: str) -> None:
    if not name.lower().endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(415, f"Only {', '.join(ALLOWED_EXTENSIONS)} files are accepted.")


def _file_error(exc: FileError) -> HTTPException:
    return HTTPException(422, {"code": exc.code, "message": str(exc), "fatal": True})


def _refused(session: Session, settings: Settings, action: str, name: str, sha: str, exc: ImportRefused) -> HTTPException:
    session.rollback()
    audit_refusal(session, actor=settings.default_actor, action=action, file_name=name, sha256=sha, reason=exc)
    return HTTPException(409, {"code": exc.code, "message": str(exc), "batch_id": exc.batch_id})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = make_engine(settings.database_url)
    factory = make_session_factory(engine)

    app = FastAPI(title="VM Dependency Mapper & Migration Wave Planner", version=__version__,
                  description="Inventory and telemetry import, validation and endpoint resolution. "
                              "No authentication yet; do not expose beyond localhost.")
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = factory

    @app.get("/api/health")
    def health(session: SessionDep):
        session.execute(select(1))
        return {"status": "ok", "version": __version__}

    # ------------------------------------------------------------ inventory

    @app.post("/api/imports/inventory", response_model=InventoryImportResult,
              responses={409: {"description": "Validation errors, policy refusal or duplicate file"}, 413: {}, 415: {},
                         422: {"description": "Fatal file error: nothing imported"}})
    async def import_inventory(
        session: SessionDep,
        file: UploadFile = File(...),
        commit: bool = Query(False, description="false = validation preview only (nothing is written)"),
        allow_partial: bool = Query(False, description="import only the valid rows (needs partial_reason)"),
        partial_reason: str | None = Query(None, max_length=1000, description="why a partial import is acceptable"),
        force: bool = Query(False, description="re-import a file identical to an earlier batch"),
        encoding: str | None = Query(None, max_length=32, description="override UTF-8, e.g. cp874"),
    ):
        name = file.filename or "upload.csv"
        _check_name(name)
        data = await file.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB.")
        try:
            parsed = parse_inventory_csv(data, max_bytes=settings.max_upload_bytes, max_rows=settings.max_inventory_rows,
                                         encoding=encoding, criticality_values=settings.criticality_values,
                                         max_invalid_ratio=settings.max_invalid_record_ratio)
        except FileError as exc:
            raise _file_error(exc) from exc

        plan = plan_import(session, parsed, data)
        issues = parsed.issues + plan.extra_issues
        batch_id = None
        if commit:
            try:
                batch_id = commit_import(session, parsed, plan, settings=settings, file_name=name, data=data,
                                         actor=settings.default_actor, allow_partial=allow_partial,
                                         partial_reason=partial_reason, force=force).id
            except ImportRefused as exc:
                raise _refused(session, settings, "inventory.import", name, plan.sha256, exc) from exc
        return InventoryImportResult(
            committed=batch_id is not None, batch_id=batch_id, file_name=name, file_sha256=plan.sha256,
            source_system=parsed.source_system, encoding=parsed.encoding, rows=parsed.row_count,
            valid_rows=len(parsed.valid_records), rejected_rows=parsed.rejected_rows, new=len(plan.new),
            updated=len(plan.updated), unchanged=len(plan.unchanged),
            errors=sum(1 for i in issues if i.severity == "error"),
            warnings=sum(1 for i in issues if i.severity == "warning"),
            already_imported_as=plan.previous_batch_id, column_map=parsed.column_map,
            issues=[IssueOut(**vars(i)) for i in issues],
            rejected_preview=[RejectedRowOut(row_number=r.row_number, raw_text=r.raw, errors=r.errors)
                              for r in parsed.rejected[:REJECTED_PREVIEW]],
        )

    # ------------------------------------------------------------ telemetry

    @app.get("/api/telemetry/parsers", response_model=list[ParserOut])
    def parsers():
        return [ParserOut(name=p.info.name, version=p.info.version, kind=p.info.kind, description=p.info.description,
                          schema_doc=p.info.schema_doc, required_fields=list(p.info.required_fields),
                          optional_fields=list(p.info.optional_fields), validated_samples=list(p.info.validated_samples),
                          validation_status=p.info.validation_status) for p in list_parsers()]

    @app.post("/api/imports/telemetry", response_model=TelemetryImportResult,
              responses={409: {"description": "Validation errors, policy refusal or duplicate file"}, 415: {},
                         422: {"description": "Fatal file error (unsupported format, schema, encoding, size): nothing imported"}})
    def import_telemetry(
        session: SessionDep,
        file: UploadFile = File(...),
        parser: str = Query(..., description="source format, see GET /api/telemetry/parsers"),
        commit: bool = Query(False),
        allow_partial: bool = Query(False),
        partial_reason: str | None = Query(None, max_length=1000),
        force: bool = Query(False),
        encoding: str | None = Query(None, max_length=32),
        timezone: str | None = Query(None, max_length=64, description="IANA zone for timestamps without offset, e.g. Asia/Bangkok"),
        window_start: datetime | None = Query(None, description="declared observation window start (with offset)"),
        window_end: datetime | None = Query(None),
    ):
        name = file.filename or "upload.csv"
        _check_name(name)
        tz = None
        if timezone:
            try:
                tz = ZoneInfo(timezone)
            except (ZoneInfoNotFoundError, ValueError) as exc:
                raise HTTPException(422, {"code": "invalid_timezone", "message": f"Unknown time zone '{timezone}'."}) from exc
        for label, w in (("window_start", window_start), ("window_end", window_end)):
            if w is not None and w.tzinfo is None:
                raise HTTPException(422, {"code": "invalid_window", "message": f"{label} needs a UTC offset."})
        if window_start and window_end and window_end < window_start:
            raise HTTPException(422, {"code": "invalid_window", "message": "window_end is before window_start."})
        ctx = ParseContext(timezone=tz, window_start=window_start, window_end=window_end,
                           max_rows=settings.max_telemetry_rows)
        try:
            info = get_parser(parser).info
            result = parse_telemetry(file.file, parser, ctx, settings, encoding)
        except FileError as exc:
            raise _file_error(exc) from exc

        prev = previous_batch(session, result.sha256, "telemetry" if result.kind == "flow" else "address")
        batch_id = None
        if commit:
            try:
                batch_id = commit_telemetry(session, result, settings=settings, file_name=name,
                                            actor=settings.default_actor, allow_partial=allow_partial,
                                            partial_reason=partial_reason, force=force, timezone_name=timezone).id
            except ImportRefused as exc:
                raise _refused(session, settings, f"{'telemetry' if result.kind == 'flow' else 'address'}.import",
                               name, result.sha256, exc) from exc
        return TelemetryImportResult(
            committed=batch_id is not None, batch_id=batch_id, file_name=name, file_sha256=result.sha256,
            parser=result.parser_name, parser_version=result.parser_version,
            parser_validation_status=info.validation_status, kind=result.kind, encoding=result.encoding,
            rows=result.rows, accepted=result.accepted, rejected=len(result.rejected), errors=result.errors,
            warnings=result.warnings, aggregated_rows=len(result.aggregator.groups) if result.aggregator else None,
            window_start=result.window_start, window_end=result.window_end, already_imported_as=prev,
            issue_counts=[IssueCount(**c) for c in result.log.summary()],
            issues=[IssueOut(**vars(i)) for i in result.log.issues()],
            rejected_preview=[RejectedRowOut(row_number=r.row_number, raw_text=r.raw, errors=r.errors)
                              for r in result.rejected[:REJECTED_PREVIEW]],
        )

    # ------------------------------------------------------------ batches, rejected rows, error report

    @app.get("/api/imports", response_model=list[BatchOut])
    def list_batches(session: SessionDep, limit: int = Query(50, ge=1, le=500),
                     source_type: str | None = Query(None, max_length=32)):
        q = select(ImportBatch)
        if source_type:
            q = q.where(ImportBatch.source_type == source_type)
        return session.scalars(q.order_by(ImportBatch.imported_at.desc()).limit(limit)).all()

    def _batch_or_404(session: Session, batch_id: str) -> ImportBatch:
        batch = session.get(ImportBatch, batch_id)
        if batch is None:
            raise HTTPException(404, "Batch not found.")
        return batch

    @app.get("/api/imports/{batch_id}", response_model=BatchDetail)
    def get_batch(batch_id: str, session: SessionDep):
        batch = session.scalar(select(ImportBatch).where(ImportBatch.id == batch_id).options(selectinload(ImportBatch.issues)))
        if batch is None:
            raise HTTPException(404, "Batch not found.")
        return batch

    @app.get("/api/imports/{batch_id}/rejected", response_model=list[RejectedRowOut])
    def rejected_rows(batch_id: str, session: SessionDep, limit: int = Query(100, ge=1, le=5000),
                      offset: int = Query(0, ge=0)):
        _batch_or_404(session, batch_id)
        return session.scalars(select(ImportRejectedRow).where(ImportRejectedRow.batch_id == batch_id)
                               .order_by(ImportRejectedRow.row_number).limit(limit).offset(offset)).all()

    @app.get("/api/imports/{batch_id}/error-report.csv")
    def error_report(batch_id: str, session: SessionDep):
        """All issues of a batch plus each rejected row verbatim. Cells are spreadsheet-safe."""
        batch = _batch_or_404(session, batch_id)
        raw_by_row = dict(session.execute(select(ImportRejectedRow.row_number, ImportRejectedRow.raw_text)
                                          .where(ImportRejectedRow.batch_id == batch_id)).all())
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(["batch_id", "file_name", "row_number", "severity", "code", "field", "message", "raw_value", "rejected_row"])
        for i in session.scalars(select(ImportIssue).where(ImportIssue.batch_id == batch_id).order_by(ImportIssue.id)):
            w.writerow([spreadsheet_safe(v) for v in (batch.id, batch.file_name, i.row_number, i.severity, i.code, i.field,
                                                      i.message, i.raw_value, raw_by_row.get(i.row_number, ""))])
        data = "﻿" + buf.getvalue()   # BOM so Excel opens UTF-8 (Thai text) correctly
        return StreamingResponse(iter([data.encode("utf-8")]), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="error-report-{batch.id}.csv"'})

    # ------------------------------------------------------------ endpoint resolution

    @app.post("/api/resolution/{batch_id}/run")
    def resolve_batch(batch_id: str, session: SessionDep):
        try:
            return run_resolution(session, settings, batch_id, settings.default_actor)
        except ResolutionError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/endpoint-mappings", response_model=EndpointMappingPage)
    def endpoint_mappings(session: SessionDep, batch_id: str | None = Query(None), status: str | None = Query(None),
                          confidence: str | None = Query(None), ip: str | None = Query(None, max_length=45),
                          needs_review: bool = Query(False, description="ambiguous, unresolved internal, or low/medium confidence"),
                          limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        q = select(EndpointMapping)
        if batch_id:
            q = q.where(EndpointMapping.flow_batch_id == batch_id)
        if status:
            q = q.where(EndpointMapping.status == status)
        if confidence:
            q = q.where(EndpointMapping.confidence == confidence)
        if ip:
            q = q.where(EndpointMapping.ip == ip)
        if needs_review:
            q = q.where(or_(EndpointMapping.status == "ambiguous",
                            (EndpointMapping.status == "unresolved") & (EndpointMapping.endpoint_class == "internal"),
                            EndpointMapping.confidence.in_(["low", "medium"])))
        total = session.scalar(select(func.count()).select_from(q.subquery())) or 0
        rows = session.scalars(q.order_by(EndpointMapping.flow_count.desc(), EndpointMapping.ip, EndpointMapping.window_start)
                               .limit(limit).offset(offset)).all()
        ids = {i for r in rows for i in ([r.vm_id] if r.vm_id else []) + list(r.candidate_vm_ids)}
        names = dict(session.execute(select(VmInventory.id, VmInventory.name).where(VmInventory.id.in_(ids))).all()) if ids else {}
        items = []
        for r in rows:
            out = EndpointMappingOut.model_validate(r)
            out.vm_name = names.get(r.vm_id)
            out.candidate_vm_names = [names.get(c, c) for c in r.candidate_vm_ids]
            items.append(out)
        return EndpointMappingPage(total=total, items=items)

    @app.get("/api/endpoint-mappings/summary")
    def mapping_summary(session: SessionDep, batch_id: str = Query(...)):
        _batch_or_404(session, batch_id)
        rows = session.execute(select(EndpointMapping.status, EndpointMapping.confidence, EndpointMapping.endpoint_class,
                                      func.count(), func.sum(EndpointMapping.flow_count))
                               .where(EndpointMapping.flow_batch_id == batch_id)
                               .group_by(EndpointMapping.status, EndpointMapping.confidence, EndpointMapping.endpoint_class)).all()
        total_flows = sum(int(r[4] or 0) for r in rows) or 0
        resolved_flows = sum(int(r[4] or 0) for r in rows if r[0] == "resolved")
        return {
            "batch_id": batch_id,
            "groups": [{"status": s, "confidence": c, "endpoint_class": k, "mappings": n, "flow_endpoints": int(f or 0)}
                       for s, c, k, n, f in rows],
            "resolved_flow_endpoint_pct": round(100 * resolved_flows / total_flows, 1) if total_flows else None,
        }

    # ------------------------------------------------------------ inventory browse

    @app.get("/api/vms", response_model=VmPage)
    def list_vms(session: SessionDep, search: str | None = Query(None, max_length=255),
                 limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        q = select(VmInventory)
        if search:
            like = f"%{search.lower()}%"
            ip_match = select(VmNetworkInterface.vm_id).where(VmNetworkInterface.ip.like(f"%{search}%"))
            q = q.where(or_(func.lower(VmInventory.name).like(like), func.lower(VmInventory.application).like(like),
                            func.lower(VmInventory.owner).like(like), VmInventory.id.in_(ip_match)))
        total = session.scalar(select(func.count()).select_from(q.subquery()))
        items = session.scalars(q.order_by(func.lower(VmInventory.name), VmInventory.id).limit(limit).offset(offset)
                                .options(selectinload(VmInventory.interfaces))).all()
        return VmPage(total=total or 0, items=items)

    return app
