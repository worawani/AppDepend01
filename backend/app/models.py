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
