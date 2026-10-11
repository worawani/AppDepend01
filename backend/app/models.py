"""ORM models. Must stay identical to the Alembic migrations; tests/test_migrations.py
fails if they drift."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ImportBatch(Base):
    __tablename__ = "import_batch"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_type: Mapped[str] = mapped_column(String(32))            # inventory | telemetry
    source_system: Mapped[str] = mapped_column(String(64))          # vcenter-csv | rvtools-vinfo | ...
    file_name: Mapped[str] = mapped_column(String(255))
    file_sha256: Mapped[str] = mapped_column(String(64), index=True)
    file_size: Mapped[int] = mapped_column(BigInteger)
    encoding: Mapped[str] = mapped_column(String(32))
    parser_version: Mapped[str] = mapped_column(String(32))
    schema_version: Mapped[str] = mapped_column(String(32))
    uploaded_by: Mapped[str] = mapped_column(String(255))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(32))                 # committed | committed_partial
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, default=0)
    observation_window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    observation_window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)

    issues: Mapped[list[ImportIssue]] = relationship(back_populates="batch", cascade="all, delete-orphan",
                                                     order_by="ImportIssue.id")


class VmInventory(Base):
    __tablename__ = "vm_inventory"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # uuid:<vcenter>:<vm_uuid> when a VM UUID is known, else name:<vcenter>:<lower(name)>
    identity_key: Mapped[str] = mapped_column(String(512), unique=True)
    vcenter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vm_uuid: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    moref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    dns_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    guest_os: Mapped[str | None] = mapped_column(String(255), nullable=True)
    power_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cluster: Mapped[str | None] = mapped_column(String(255), nullable=True)
    datacenter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    application: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tier: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_import_batch_id: Mapped[str] = mapped_column(ForeignKey("import_batch.id"))
    last_import_batch_id: Mapped[str] = mapped_column(ForeignKey("import_batch.id"))
    source_row_ref: Mapped[str] = mapped_column(String(128))       # <batch id>:<row number>
    raw_record: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    interfaces: Mapped[list[VmNetworkInterface]] = relationship(back_populates="vm", cascade="all, delete-orphan",
                                                                order_by="VmNetworkInterface.id")


class VmNetworkInterface(Base):
    __tablename__ = "vm_network_interface"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vm_id: Mapped[str] = mapped_column(ForeignKey("vm_inventory.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    network: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_batch_id: Mapped[str] = mapped_column(ForeignKey("import_batch.id"))
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    vm: Mapped[VmInventory] = relationship(back_populates="interfaces")


class ImportIssue(Base):
    __tablename__ = "import_issue"
    __table_args__ = (Index("ix_import_issue_batch_severity", "batch_id", "severity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("import_batch.id", ondelete="CASCADE"))
    row_number: Mapped[int | None] = mapped_column(Integer, nullable=True)   # None = file-level
    severity: Mapped[str] = mapped_column(String(16))                        # error | warning | info
    code: Mapped[str] = mapped_column(String(64))
    field: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    raw_value: Mapped[str | None] = mapped_column(Text, nullable=True)

    batch: Mapped[ImportBatch] = relationship(back_populates="issues")


class AuditEvent(Base):
    __tablename__ = "audit_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


# ---------------------------------------------------------------- Phase 2 (revision 0002)

_BigId = BigInteger().with_variant(Integer, "sqlite")   # SQLite autoincrements only INTEGER PRIMARY KEY


class ImportRejectedRow(Base):
    """A record that failed validation, kept verbatim with its errors (never silently discarded)."""
    __tablename__ = "import_rejected_row"

    id: Mapped[int] = mapped_column(_BigId, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("import_batch.id", ondelete="CASCADE"), index=True)
    row_number: Mapped[int] = mapped_column(Integer)
    raw_text: Mapped[str] = mapped_column(Text)
    errors: Mapped[list] = mapped_column(JSON, default=list)


class FlowObservation(Base):
    """Telemetry aggregated per (hour, src, dst, protocol, dst port, action). The original
    file stays identifiable through the batch hash; sample_refs point back to source records."""
    __tablename__ = "flow_observation"
    __table_args__ = (Index("ix_flow_observation_batch_bucket", "batch_id", "bucket_start"),)

    id: Mapped[int] = mapped_column(_BigId, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("import_batch.id", ondelete="CASCADE"))
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)       # post-DNAT address when the source logs NAT
    dst_ip_original: Mapped[str | None] = mapped_column(String(45), nullable=True)
    protocol: Mapped[str] = mapped_column(String(8))
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(16))                    # allow | deny | observed | unknown
    record_count: Mapped[int] = mapped_column(Integer)
    flow_count: Mapped[int] = mapped_column(BigInteger)
    bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    packets: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reverse_suspect_count: Mapped[int] = mapped_column(Integer, default=0)
    sample_refs: Mapped[list] = mapped_column(JSON, default=list)


class AddressRecord(Base):
    """Time-bounded IP <-> hostname/MAC evidence from DNS or DHCP exports."""
    __tablename__ = "address_record"

    id: Mapped[int] = mapped_column(_BigId, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("import_batch.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    record_type: Mapped[str] = mapped_column(String(16))               # dns_a | dns_ptr | dhcp_lease | static
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_row_ref: Mapped[str] = mapped_column(String(128))


class EndpointMapping(Base):
    """Result of resolving one observed IP for one flow batch over a time window.
    Unresolved and ambiguous endpoints are stored too; nothing is forced onto a VM."""
    __tablename__ = "endpoint_mapping"

    id: Mapped[int] = mapped_column(_BigId, primary_key=True, autoincrement=True)
    flow_batch_id: Mapped[str] = mapped_column(ForeignKey("import_batch.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    endpoint_class: Mapped[str] = mapped_column(String(16))            # internal | external | special
    status: Mapped[str] = mapped_column(String(16), index=True)        # resolved | ambiguous | unresolved
    vm_id: Mapped[str | None] = mapped_column(ForeignKey("vm_inventory.id", ondelete="SET NULL"), nullable=True, index=True)
    method: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(8))                 # high | medium | low | none
    candidate_vm_ids: Mapped[list] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    bucket_count: Mapped[int] = mapped_column(Integer)
    flow_count: Mapped[int] = mapped_column(BigInteger)
    resolver_version: Mapped[str] = mapped_column(String(32))
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
