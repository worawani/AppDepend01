"""Import commit policy shared by every importer (approved decision 3).

* Fatal file problems never reach this point (FileError → the file is rejected).
* Record-level errors block the commit by default.
* Importing only the valid records is an explicit decision: allow_partial=true **and** a
  written reason. It is refused outright if an administrator disabled partial imports.
  The decision, the reason and the actor are stored on the batch and in the audit log.
* Rejected records are stored verbatim with their errors.
* An identical file (same SHA-256) needs force=true to be imported again."""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..importers.common import Issue, RejectedRow
from ..models import AuditEvent, ImportBatch, ImportIssue, ImportRejectedRow


class ImportRefused(Exception):
    """Commit refused by policy. Nothing was written (except the audit record of the refusal)."""

    def __init__(self, code: str, message: str, batch_id: str | None = None):
        super().__init__(message)
        self.code = code
        self.batch_id = batch_id


def previous_batch(session: Session, sha256: str, source_type: str) -> str | None:
    return session.scalar(select(ImportBatch.id).where(ImportBatch.file_sha256 == sha256,
                                                       ImportBatch.source_type == source_type)
                          .order_by(ImportBatch.imported_at.desc()).limit(1))


def enforce_commit_policy(settings: Settings, *, errors: int, rejected: int, allow_partial: bool,
                          partial_reason: str | None, previous_batch_id: str | None, force: bool) -> dict | None:
    """Raises ImportRefused, or returns the partial-import decision record (None if not partial)."""
    if previous_batch_id and not force:
        raise ImportRefused("duplicate_file", f"This exact file was already imported (batch {previous_batch_id}). "
                            "Pass force=true to import it again.", previous_batch_id)
    if not errors:
        return None
    if not allow_partial:
        raise ImportRefused("validation_errors", f"{errors:,} validation error(s) in {rejected:,} record(s). Fix the "
                            "file, or explicitly import only the valid records (allow_partial=true with a "
                            "partial_reason). Rejected records are then kept with their errors.")
    if not settings.allow_partial_imports:
        raise ImportRefused("partial_disabled", "Partial imports are disabled by the administrator "
                            "(VDM_ALLOW_PARTIAL_IMPORTS=false). Fix the file and import it whole.")
    reason = (partial_reason or "").strip()
    if len(reason) < settings.partial_reason_min_length:
        raise ImportRefused("reason_required", "A partial import needs a written reason of at least "
                            f"{settings.partial_reason_min_length} characters (partial_reason). It is stored in "
                            "the audit log.")
    return {"reason": reason, "rejected_records": rejected, "errors": errors}


def store_issues_and_rejects(session: Session, batch: ImportBatch, issues: Iterable[Issue],
                             rejected: list[RejectedRow], max_rejected: int) -> int:
    """Returns the number of rejected rows NOT stored because of the cap (reported, never hidden)."""
    issue_rows = [dict(batch_id=batch.id, row_number=i.row_number, severity=i.severity, code=i.code, field=i.field,
                       message=i.message, raw_value=i.raw_value) for i in issues]
    kept = rejected[:max_rejected]
    dropped = len(rejected) - len(kept)
    if dropped:
        issue_rows.append(dict(batch_id=batch.id, row_number=None, severity="warning", code="rejected_rows_truncated",
                               field=None, message=f"{len(rejected):,} rows were rejected; only the first {len(kept):,} "
                               "are stored verbatim (VDM_MAX_REJECTED_ROWS_STORED). Fix the source file.", raw_value=None))
    if issue_rows:
        session.execute(insert(ImportIssue), issue_rows)
    if kept:
        session.execute(insert(ImportRejectedRow), [dict(batch_id=batch.id, row_number=r.row_number, raw_text=r.raw,
                                                         errors=r.errors) for r in kept])
    return dropped


def audit_import(session: Session, batch: ImportBatch, actor: str, action: str, details: dict) -> None:
    session.add(AuditEvent(actor=actor, action=action, entity_type="import_batch", entity_id=batch.id,
                           outcome=batch.status, details=details))


def audit_refusal(session: Session, *, actor: str, action: str, file_name: str, sha256: str,
                  reason: ImportRefused) -> None:
    session.add(AuditEvent(actor=actor, action=action, entity_type="import_batch", entity_id=reason.batch_id,
                           outcome="refused", details={"file_name": file_name, "sha256": sha256, "code": reason.code,
                                                       "message": str(reason)}))
    session.commit()
