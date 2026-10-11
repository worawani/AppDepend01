import pytest
from sqlalchemy import select

from app.config import Settings
from app.importers.common import FileError
from app.importers.inventory import parse_inventory_csv
from app.models import AuditEvent, ImportRejectedRow
from app.sampledata import CANONICAL_HEADER, error_rows, to_csv
from app.services.inventory import commit_import, plan_import
from app.services.policy import ImportRefused, enforce_commit_policy

S = Settings(database_url="sqlite://")
REASON = "Rejected rows are retired VMs, confirmed by owner"


def policy(**kw):
    args = dict(errors=0, rejected=0, allow_partial=False, partial_reason=None, previous_batch_id=None, force=False)
    args.update(kw)
    settings = args.pop("settings", S)
    return enforce_commit_policy(settings, **args)


def refused(**kw) -> str:
    with pytest.raises(ImportRefused) as e:
        policy(**kw)
    return e.value.code


def test_clean_file_passes():
    assert policy() is None


def test_errors_block_by_default():
    assert refused(errors=3, rejected=2) == "validation_errors"


def test_partial_needs_written_reason():
    assert refused(errors=3, rejected=2, allow_partial=True) == "reason_required"
    assert refused(errors=3, rejected=2, allow_partial=True, partial_reason="ok") == "reason_required"
    decision = policy(errors=3, rejected=2, allow_partial=True, partial_reason=f"  {REASON}  ")
    assert decision == {"reason": REASON, "rejected_records": 2, "errors": 3}


def test_admin_can_disable_partial_imports():
    off = Settings(database_url="sqlite://", allow_partial_imports=False)
    assert refused(settings=off, errors=1, rejected=1, allow_partial=True, partial_reason=REASON) == "partial_disabled"
    assert policy(settings=off) is None     # clean files still import


def test_duplicate_file_checked_first():
    assert refused(previous_batch_id="b1", errors=5, rejected=5) == "duplicate_file"
    assert policy(previous_batch_id="b1", force=True) is None


def test_allow_partial_without_errors_is_a_normal_import():
    assert policy(allow_partial=True) is None


# ---------------------------------------------------------------- inventory uses the same policy

LIMITS = dict(max_bytes=10_000_000, max_rows=5000)


def test_inventory_partial_import_stores_rejected_rows_and_decision(session):
    data = to_csv(error_rows(), CANONICAL_HEADER)
    parsed = parse_inventory_csv(data, **LIMITS)
    plan = plan_import(session, parsed, data)
    batch = commit_import(session, parsed, plan, settings=S, file_name="inv.csv", data=data, actor="alice",
                          allow_partial=True, partial_reason=REASON)
    assert batch.summary["partial_import"] == {"reason": REASON, "rejected_records": 4, "errors": 4, "decided_by": "alice"}
    rows = session.scalars(select(ImportRejectedRow).where(ImportRejectedRow.batch_id == batch.id)
                           .order_by(ImportRejectedRow.row_number)).all()
    assert [r.row_number for r in rows] == [4, 5, 6, 7]
    assert "not-a-uuid" in rows[1].raw_text and rows[1].errors[0]["code"] == "invalid_uuid"
    audit = session.scalar(select(AuditEvent).where(AuditEvent.entity_id == batch.id))
    assert audit.details["partial_import"]["reason"] == REASON and audit.actor == "alice"


def test_inventory_mostly_invalid_is_fatal():
    rows = "vm_name,vm_uuid\n" + "".join(f"VM{i},bad-uuid\n" for i in range(30)) + "OK1,\nOK2,\n"
    with pytest.raises(FileError) as e:
        parse_inventory_csv(rows.encode(), **LIMITS)
    assert e.value.code == "too_many_invalid_records"
