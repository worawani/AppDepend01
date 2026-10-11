"""Inventory import: preview (diff against the database, no writes) and commit
(batch + upsert + issues + audit, in one transaction)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..importers.inventory import PARSER_VERSION, SCHEMA_VERSION, InventoryRecord, Issue, ParseResult
from ..models import AuditEvent, ImportBatch, ImportIssue, VmInventory, VmNetworkInterface, utcnow


class ImportRefused(Exception):
    """Commit refused by policy (errors present, or the identical file was already imported)."""

    def __init__(self, code: str, message: str, batch_id: str | None = None):
        super().__init__(message)
        self.code = code
        self.batch_id = batch_id


@dataclass
class ImportPlan:
    sha256: str
    new: list[InventoryRecord] = field(default_factory=list)
    updated: list[tuple[InventoryRecord, VmInventory, dict]] = field(default_factory=list)
    unchanged: list[tuple[InventoryRecord, VmInventory]] = field(default_factory=list)
    extra_issues: list[Issue] = field(default_factory=list)
    previous_batch_id: str | None = None    # set when this exact file was committed before


def file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _interfaces(rec: InventoryRecord) -> list[tuple[str | None, str | None, str | None]]:
    """(ip, mac, network) tuples. A CSV row does not say which IP belongs to which vNIC, so a
    MAC/network is attached only when the VM has exactly one."""
    mac = rec.macs[0] if len(rec.macs) == 1 else None
    net = rec.networks[0] if len(rec.networks) == 1 else None
    rows = [(ip, mac, net) for ip in rec.ips]
    if not rows:
        rows = [(None, m, net) for m in rec.macs]
    elif len(rec.macs) > 1:
        rows += [(None, m, None) for m in rec.macs]
    if not rows and rec.networks:
        rows = [(None, None, n) for n in rec.networks]
    return sorted(set(rows), key=lambda t: tuple(x or "" for x in t))


INTERFACE_FIELDS = ("ip_addresses", "mac_addresses", "networks")


def updatable_fields(parsed: ParseResult) -> list[str]:
    """Only columns present in this file may change stored values. A vCenter export without an
    'owner' column must not wipe owners that came from the CMDB file."""
    return [a for a in InventoryRecord.ATTRS if a in parsed.column_map]


def _if_key(rows) -> list[tuple[str, str, str]]:
    return sorted(tuple(x or "" for x in t) for t in rows)


def _carry_over(rec: InventoryRecord, vm: VmInventory, column_map: dict) -> InventoryRecord:
    """Interface parts this file has no column for (e.g. MACs in an RVTools vInfo export)
    keep their stored values instead of being dropped."""
    def stored(attr: str) -> list[str]:
        return sorted({getattr(i, attr) for i in vm.interfaces if getattr(i, attr)})
    return replace(rec,
                   ips=rec.ips if "ip_addresses" in column_map else stored("ip"),
                   macs=rec.macs if "mac_addresses" in column_map else stored("mac"),
                   networks=rec.networks if "networks" in column_map else stored("network"))


def _changes(rec: InventoryRecord, vm: VmInventory, fields: list[str], interfaces_present: bool) -> dict:
    changes = {}
    for attr in fields:
        model_attr = "name" if attr == "vm_name" else attr
        old, new = getattr(vm, model_attr), getattr(rec, attr)
        if new is None:          # blanks never clear a stored value
            continue
        if old != new:
            changes[model_attr] = {"old": old, "new": new}
    new_if = _interfaces(rec)
    if interfaces_present and new_if:
        old_if = [(i.ip, i.mac, i.network) for i in vm.interfaces]
        if _if_key(old_if) != _if_key(new_if):
            changes["interfaces"] = {"old": [list(t) for t in _if_key(old_if)], "new": [list(t) for t in _if_key(new_if)]}
    return changes


def plan_import(session: Session, parsed: ParseResult, data: bytes) -> ImportPlan:
    plan = ImportPlan(sha256=file_sha256(data))
    prev = session.scalar(select(ImportBatch.id).where(ImportBatch.file_sha256 == plan.sha256,
                                                       ImportBatch.source_type == "inventory")
                          .order_by(ImportBatch.imported_at.desc()).limit(1))
    plan.previous_batch_id = prev

    valid = parsed.valid_records
    keys = [r.identity_key for r in valid]
    existing: dict[str, VmInventory] = {}
    for chunk_start in range(0, len(keys), 500):
        chunk = keys[chunk_start:chunk_start + 500]
        for vm in session.scalars(select(VmInventory).where(VmInventory.identity_key.in_(chunk))):
            existing[vm.identity_key] = vm

    new_names = {r.vm_name.lower() for r in valid if r.identity_key not in existing}
    name_hits: dict[str, list[VmInventory]] = {}
    names = list(new_names)
    for chunk_start in range(0, len(names), 500):
        for vm in session.scalars(select(VmInventory).where(func.lower(VmInventory.name).in_(names[chunk_start:chunk_start + 500]))):
            name_hits.setdefault(vm.name.lower(), []).append(vm)

    fields = updatable_fields(parsed)
    interfaces_present = any(f in parsed.column_map for f in INTERFACE_FIELDS)
    for rec in valid:
        vm = existing.get(rec.identity_key)
        if vm is None:
            plan.new.append(rec)
            for other in name_hits.get(rec.vm_name.lower(), []):
                plan.extra_issues.append(Issue(
                    "warning", "possible_duplicate",
                    f"New record, but VM '{other.name}' already exists under identity '{other.identity_key}'. "
                    "If it is the same VM, its identifier changed (UUID added/removed, or vCenter column differs) "
                    "and you will get a duplicate.", rec.row_number, "vm_uuid"))
            continue
        rec = _carry_over(rec, vm, parsed.column_map)
        changes = _changes(rec, vm, fields, interfaces_present)
        if "interfaces" in changes:
            old_ips = {t[0] for t in changes["interfaces"]["old"] if t[0]}
            new_ips = {t[0] for t in changes["interfaces"]["new"] if t[0]}
            if old_ips - new_ips:
                plan.extra_issues.append(Issue(
                    "warning", "ips_removed",
                    f"Import removes IP(s) {', '.join(sorted(old_ips - new_ips))} from '{vm.name}'. Expected if they were "
                    "re-assigned; wrong if this file only lists a primary IP.", rec.row_number, "ip_addresses"))
        if changes:
            plan.updated.append((rec, vm, changes))
        else:
            plan.unchanged.append((rec, vm))
    return plan


def commit_import(session: Session, parsed: ParseResult, plan: ImportPlan, *, file_name: str, data: bytes,
                  actor: str, allow_partial: bool = False, force: bool = False) -> ImportBatch:
    errors = parsed.count("error")
    if plan.previous_batch_id and not force:
        raise ImportRefused("duplicate_file", "This exact file was already imported "
                            f"(batch {plan.previous_batch_id}). Pass force=true to import it again.", plan.previous_batch_id)
    if errors and not allow_partial:
        raise ImportRefused("validation_errors", f"{errors} validation error(s). Fix the file, or pass "
                            "allow_partial=true to import only the valid rows (the rejected rows are recorded).")

    all_issues = parsed.issues + plan.extra_issues
    batch = ImportBatch(
        source_type="inventory", source_system=parsed.source_system, file_name=file_name[:255],
        file_sha256=plan.sha256, file_size=len(data), encoding=parsed.encoding, parser_version=PARSER_VERSION,
        schema_version=SCHEMA_VERSION, uploaded_by=actor, status="committed_partial" if errors else "committed",
        row_count=parsed.row_count, accepted_count=len(parsed.valid_records), rejected_count=parsed.rejected_rows,
        warning_count=sum(1 for i in all_issues if i.severity == "warning"),
        summary={"new": len(plan.new), "updated": len(plan.updated), "unchanged": len(plan.unchanged),
                 "errors": errors, "column_map": parsed.column_map, "forced": bool(plan.previous_batch_id and force)},
    )
    session.add(batch)
    session.flush()
    now = utcnow()

    def touch(vm: VmInventory, rec: InventoryRecord) -> None:
        vm.last_import_batch_id = batch.id
        vm.source_row_ref = f"{batch.id}:{rec.row_number}"
        vm.raw_record = rec.raw

    def replace_interfaces(vm: VmInventory, rec: InventoryRecord) -> None:
        vm.interfaces.clear()
        for ip, mac, net in _interfaces(rec):
            vm.interfaces.append(VmNetworkInterface(ip=ip, mac=mac, network=net, source_batch_id=batch.id))

    for rec in plan.new:
        vm = VmInventory(identity_key=rec.identity_key, first_import_batch_id=batch.id, created_at=now, updated_at=now,
                         name=rec.vm_name, **{a: getattr(rec, a) for a in InventoryRecord.ATTRS[1:]})
        touch(vm, rec)
        replace_interfaces(vm, rec)
        session.add(vm)
    for rec, vm, changes in plan.updated:
        for attr, change in changes.items():
            if attr != "interfaces":
                setattr(vm, attr, change["new"])
        if "interfaces" in changes:
            replace_interfaces(vm, rec)
        vm.updated_at = now
        touch(vm, rec)
    for rec, vm in plan.unchanged:
        touch(vm, rec)

    for i in all_issues:
        session.add(ImportIssue(batch_id=batch.id, row_number=i.row_number, severity=i.severity, code=i.code,
                                field=i.field, message=i.message, raw_value=i.raw_value))
    session.add(AuditEvent(
        actor=actor, action="inventory.import", entity_type="import_batch", entity_id=batch.id,
        outcome=batch.status,
        details={"file_name": file_name, "sha256": plan.sha256, "rows": parsed.row_count, **batch.summary,
                 "updated_vms": {vm.id: ch for _, vm, ch in plan.updated[:200]}},
    ))
    session.commit()
    return batch


def audit_refusal(session: Session, *, actor: str, file_name: str, sha256: str, reason: ImportRefused) -> None:
    session.add(AuditEvent(actor=actor, action="inventory.import", entity_type="import_batch", entity_id=reason.batch_id,
                           outcome="refused", details={"file_name": file_name, "sha256": sha256, "code": reason.code,
                                                       "message": str(reason)}))
    session.commit()
