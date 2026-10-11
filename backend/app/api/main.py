"""FastAPI application. Phase 1 has no authentication: bind to localhost only
(see docs/mvp/PLAN.md, decision D8)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from .. import __version__
from ..config import Settings, get_settings
from ..db import make_engine, make_session_factory
from ..importers.inventory import InventoryFileError, parse_inventory_csv
from ..models import ImportBatch, VmInventory, VmNetworkInterface
from ..services.inventory import ImportRefused, audit_refusal, commit_import, plan_import
from .schemas import BatchDetail, BatchOut, InventoryImportResult, IssueOut, VmPage

ALLOWED_EXTENSIONS = (".csv", ".txt")


def get_session(request: Request) -> Iterator[Session]:
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


SessionDep = Annotated[Session, Depends(get_session)]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = make_engine(settings.database_url)
    factory = make_session_factory(engine)

    app = FastAPI(title="VM Dependency Mapper & Migration Wave Planner", version=__version__,
                  description="Phase 1: inventory import. No authentication yet; do not expose beyond localhost.")
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = factory

    @app.get("/api/health")
    def health(session: SessionDep):
        session.execute(select(1))
        return {"status": "ok", "version": __version__}

    @app.post("/api/imports/inventory", response_model=InventoryImportResult,
              responses={409: {"description": "Validation errors or duplicate file"}, 413: {}, 415: {}, 422: {}})
    async def import_inventory(
        session: SessionDep,
        file: UploadFile = File(...),
        commit: bool = Query(False, description="false = preview only (nothing is written)"),
        allow_partial: bool = Query(False, description="commit valid rows even if some rows have errors"),
        force: bool = Query(False, description="re-import a file identical to an earlier batch"),
        encoding: str | None = Query(None, max_length=32, description="override UTF-8, e.g. cp874"),
    ):
        name = file.filename or "upload.csv"
        if not name.lower().endswith(ALLOWED_EXTENSIONS):
            raise HTTPException(415, f"Only {', '.join(ALLOWED_EXTENSIONS)} files are accepted.")
        data = await file.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB.")
        try:
            parsed = parse_inventory_csv(data, max_bytes=settings.max_upload_bytes, max_rows=settings.max_inventory_rows,
                                         encoding=encoding, criticality_values=settings.criticality_values)
        except InventoryFileError as exc:
            raise HTTPException(422, {"code": exc.code, "message": str(exc)}) from exc

        plan = plan_import(session, parsed, data)
        issues = parsed.issues + plan.extra_issues
        batch_id = None
        if commit:
            try:
                batch_id = commit_import(session, parsed, plan, file_name=name, data=data, actor=settings.default_actor,
                                         allow_partial=allow_partial, force=force).id
            except ImportRefused as exc:
                session.rollback()
                audit_refusal(session, actor=settings.default_actor, file_name=name, sha256=plan.sha256, reason=exc)
                raise HTTPException(409, {"code": exc.code, "message": str(exc), "batch_id": exc.batch_id}) from exc
        return InventoryImportResult(
            committed=batch_id is not None, batch_id=batch_id, file_name=name, file_sha256=plan.sha256,
            source_system=parsed.source_system, encoding=parsed.encoding, rows=parsed.row_count,
            valid_rows=len(parsed.valid_records), rejected_rows=parsed.rejected_rows, new=len(plan.new),
            updated=len(plan.updated), unchanged=len(plan.unchanged),
            errors=sum(1 for i in issues if i.severity == "error"),
            warnings=sum(1 for i in issues if i.severity == "warning"),
            already_imported_as=plan.previous_batch_id, column_map=parsed.column_map,
            issues=[IssueOut(**vars(i)) for i in issues],
        )

    @app.get("/api/imports", response_model=list[BatchOut])
    def list_batches(session: SessionDep, limit: int = Query(50, ge=1, le=500)):
        return session.scalars(select(ImportBatch).order_by(ImportBatch.imported_at.desc()).limit(limit)).all()

    @app.get("/api/imports/{batch_id}", response_model=BatchDetail)
    def get_batch(batch_id: str, session: SessionDep):
        batch = session.scalar(select(ImportBatch).where(ImportBatch.id == batch_id).options(selectinload(ImportBatch.issues)))
        if batch is None:
            raise HTTPException(404, "Batch not found.")
        return batch

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
