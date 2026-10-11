import time

import pytest
from sqlalchemy import func, select

from app.importers.inventory import parse_inventory_csv
from app.models import AuditEvent, ImportBatch, ImportIssue, VmInventory, VmNetworkInterface
from app.sampledata import CANONICAL_HEADER, canonical_rows, error_rows, rvtools_rows, to_csv
from app.services.inventory import ImportRefused, commit_import, plan_import

LIMITS = dict(max_bytes=50_000_000, max_rows=20_000, criticality_values=["critical", "high", "medium", "low"])


def run(session, data: bytes, name="inv.csv", **kw):
    parsed = parse_inventory_csv(data, **LIMITS)
    plan = plan_import(session, parsed, data)
    batch = commit_import(session, parsed, plan, file_name=name, data=data, actor="tester", **kw)
    return parsed, plan, batch


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def test_new_then_unchanged_then_updated(session):
    data = to_csv(canonical_rows(), CANONICAL_HEADER)
    _, plan, b1 = run(session, data)
    assert (len(plan.new), b1.status) == (15, "committed")
    assert count(session, VmInventory) == 15
    assert count(session, VmNetworkInterface) == 16    # HR-SQL01 has two IPs

    _, plan, _ = run(session, data, force=True)
    assert (len(plan.new), len(plan.updated), len(plan.unchanged)) == (0, 0, 15)

    rows = canonical_rows()
    rows[0]["owner"] = "new-owner@corp.example"
    rows[1]["ip_addresses"] = "10.10.0.111"
    _, plan, b3 = run(session, to_csv(rows, CANONICAL_HEADER))
    assert len(plan.updated) == 2
    changes = {vm.name: ch for _, vm, ch in plan.updated}
    assert changes["DC01"]["owner"]["new"] == "new-owner@corp.example"
    assert "interfaces" in changes["DC02"]
    dc02 = session.scalar(select(VmInventory).where(VmInventory.name == "DC02"))
    assert [i.ip for i in dc02.interfaces] == ["10.10.0.111"]
    assert dc02.first_import_batch_id == b1.id and dc02.last_import_batch_id == b3.id
    assert count(session, VmInventory) == 15


def test_identical_file_blocked_unless_forced(session):
    data = to_csv(canonical_rows(), CANONICAL_HEADER)
    _, _, b1 = run(session, data)
    with pytest.raises(ImportRefused) as e:
        run(session, data)
    assert e.value.code == "duplicate_file" and e.value.batch_id == b1.id
    session.rollback()
    _, _, b2 = run(session, data, force=True)
    assert b2.summary["forced"] is True


def test_errors_block_commit_unless_partial(session):
    data = to_csv(error_rows(), CANONICAL_HEADER)
    with pytest.raises(ImportRefused) as e:
        run(session, data)
    assert e.value.code == "validation_errors"
    session.rollback()
    assert count(session, VmInventory) == 0 and count(session, ImportBatch) == 0

    _, _, batch = run(session, data, allow_partial=True)
    assert batch.status == "committed_partial"
    assert (batch.accepted_count, batch.rejected_count) == (8, 4)
    assert count(session, VmInventory) == 8
    stored = session.scalars(select(ImportIssue.code).where(ImportIssue.batch_id == batch.id)).all()
    assert stored.count("duplicate_identity") == 2 and "shared_ip" in stored


def test_partial_vendor_export_does_not_wipe_other_fields(session):
    """A vCenter/RVTools export has no owner/application/criticality columns or MACs.
    Importing it after the CMDB-enriched file must not erase those values."""
    run(session, to_csv(canonical_rows(), CANONICAL_HEADER))
    _, plan, _ = run(session, to_csv(rvtools_rows()))
    assert len(plan.unchanged) == 14 and len(plan.updated) == 1     # HR-SQL01 loses its 2nd IP
    assert [i.code for i in plan.extra_issues] == ["ips_removed"]
    dc01 = session.scalar(select(VmInventory).where(VmInventory.name == "DC01"))
    assert dc01.owner == "active-owner@corp.example" and dc01.criticality == "critical"
    assert dc01.interfaces[0].mac == "00:50:56:00:00:01"


def test_blank_value_does_not_clear(session):
    run(session, b"vm_name,owner\nA,alice\n")
    _, plan, _ = run(session, b"vm_name,owner\nA,\n")
    assert len(plan.unchanged) == 1
    assert session.scalar(select(VmInventory.owner)) == "alice"


def test_possible_duplicate_when_identifier_changes(session):
    run(session, b"vm_name,ip_addresses\nAPP01,10.0.0.1\n")              # name identity
    data = b"vm_name,vm_uuid,ip_addresses\nAPP01,11111111-1111-1111-1111-111111111111,10.0.0.1\n"
    parsed = parse_inventory_csv(data, **LIMITS)
    plan = plan_import(session, parsed, data)
    assert len(plan.new) == 1
    assert [i.code for i in plan.extra_issues] == ["possible_duplicate"]


def test_audit_event_written(session):
    _, _, batch = run(session, to_csv(canonical_rows(), CANONICAL_HEADER), name="vc.csv")
    ev = session.scalar(select(AuditEvent))
    assert (ev.actor, ev.action, ev.entity_id, ev.outcome) == ("tester", "inventory.import", batch.id, "committed")
    assert ev.details["new"] == 15 and ev.details["file_name"] == "vc.csv"


def test_provenance_fields(session):
    _, _, batch = run(session, to_csv(canonical_rows(), CANONICAL_HEADER))
    vm = session.scalar(select(VmInventory).where(VmInventory.name == "HR-WEB01"))
    assert vm.source_row_ref == f"{batch.id}:5"
    assert vm.raw_record["vm_name"] == "HR-WEB01"
    assert batch.parser_version and batch.schema_version == "inventory-csv-v1" and len(batch.file_sha256) == 64


def test_1000_vms_twice_no_duplicates(session):
    """Acceptance criterion (reference §11): 1,000 VMs import without duplicate records."""
    data = to_csv(canonical_rows(1000), CANONICAL_HEADER)
    t0 = time.perf_counter()
    _, plan, _ = run(session, data)
    first = time.perf_counter() - t0
    assert len(plan.new) == 1000
    _, plan, _ = run(session, data, force=True)
    assert len(plan.unchanged) == 1000
    assert count(session, VmInventory) == 1000
    assert count(session, VmNetworkInterface) == 1000
    assert first < 30, f"1,000-VM import took {first:.1f}s"
