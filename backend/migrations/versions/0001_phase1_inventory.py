"""Phase 1: import batches, VM inventory, network interfaces, import issues, audit events.

Revision ID: 0001
Revises:
Create Date: 2026-10-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "import_batch",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_system", sa.String(64), nullable=False),
        sa.Column("file_name", sa.String(255), nullable=False),
        sa.Column("file_sha256", sa.String(64), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("encoding", sa.String(32), nullable=False),
        sa.Column("parser_version", sa.String(32), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("uploaded_by", sa.String(255), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("accepted_count", sa.Integer(), nullable=False),
        sa.Column("rejected_count", sa.Integer(), nullable=False),
        sa.Column("warning_count", sa.Integer(), nullable=False),
        sa.Column("observation_window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observation_window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=False),
    )
    op.create_index("ix_import_batch_file_sha256", "import_batch", ["file_sha256"])

    op.create_table(
        "vm_inventory",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("identity_key", sa.String(512), nullable=False),
        sa.Column("vcenter", sa.String(255), nullable=True),
        sa.Column("vm_uuid", sa.String(36), nullable=True),
        sa.Column("moref", sa.String(64), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("dns_name", sa.String(255), nullable=True),
        sa.Column("guest_os", sa.String(255), nullable=True),
        sa.Column("power_state", sa.String(32), nullable=True),
        sa.Column("cluster", sa.String(255), nullable=True),
        sa.Column("datacenter", sa.String(255), nullable=True),
        sa.Column("environment", sa.String(64), nullable=True),
        sa.Column("application", sa.String(255), nullable=True),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("criticality", sa.String(32), nullable=True),
        sa.Column("tier", sa.String(64), nullable=True),
        sa.Column("first_import_batch_id", sa.String(36), sa.ForeignKey("import_batch.id"), nullable=False),
        sa.Column("last_import_batch_id", sa.String(36), sa.ForeignKey("import_batch.id"), nullable=False),
        sa.Column("source_row_ref", sa.String(128), nullable=False),
        sa.Column("raw_record", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("identity_key"),
    )
    op.create_index("ix_vm_inventory_vm_uuid", "vm_inventory", ["vm_uuid"])
    op.create_index("ix_vm_inventory_name", "vm_inventory", ["name"])

    op.create_table(
        "vm_network_interface",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("vm_id", sa.String(36), sa.ForeignKey("vm_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("mac", sa.String(17), nullable=True),
        sa.Column("network", sa.String(255), nullable=True),
        sa.Column("source_batch_id", sa.String(36), sa.ForeignKey("import_batch.id"), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_vm_network_interface_vm_id", "vm_network_interface", ["vm_id"])
    op.create_index("ix_vm_network_interface_ip", "vm_network_interface", ["ip"])
    op.create_index("ix_vm_network_interface_mac", "vm_network_interface", ["mac"])

    op.create_table(
        "import_issue",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("import_batch.id", ondelete="CASCADE"), nullable=False),
        sa.Column("row_number", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("field", sa.String(64), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=True),
    )
    op.create_index("ix_import_issue_batch_severity", "import_issue", ["batch_id", "severity"])

    op.create_table(
        "audit_event",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(64), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_audit_event_at", "audit_event", ["at"])


def downgrade() -> None:
    op.drop_table("audit_event")
    op.drop_table("import_issue")
    op.drop_table("vm_network_interface")
    op.drop_table("vm_inventory")
    op.drop_table("import_batch")
