"""Phase 2: rejected rows, aggregated flow observations, DNS/DHCP address records, endpoint mappings.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

BigId = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "import_rejected_row",
        sa.Column("id", BigId, primary_key=True, autoincrement=True),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("import_batch.id", ondelete="CASCADE"), nullable=False),
        sa.Column("row_number", sa.Integer(), nullable=False),
        sa.Column("raw_text", sa.Text(), nullable=False),
        sa.Column("errors", sa.JSON(), nullable=False),
    )
    op.create_index("ix_import_rejected_row_batch_id", "import_rejected_row", ["batch_id"])

    op.create_table(
        "flow_observation",
        sa.Column("id", BigId, primary_key=True, autoincrement=True),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("import_batch.id", ondelete="CASCADE"), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("dst_ip", sa.String(45), nullable=False),
        sa.Column("dst_ip_original", sa.String(45), nullable=True),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("flow_count", sa.BigInteger(), nullable=False),
        sa.Column("bytes", sa.BigInteger(), nullable=True),
        sa.Column("packets", sa.BigInteger(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reverse_suspect_count", sa.Integer(), nullable=False),
        sa.Column("sample_refs", sa.JSON(), nullable=False),
    )
    op.create_index("ix_flow_observation_batch_bucket", "flow_observation", ["batch_id", "bucket_start"])
    op.create_index("ix_flow_observation_src_ip", "flow_observation", ["src_ip"])
    op.create_index("ix_flow_observation_dst_ip", "flow_observation", ["dst_ip"])

    op.create_table(
        "address_record",
        sa.Column("id", BigId, primary_key=True, autoincrement=True),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("import_batch.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("mac", sa.String(17), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("record_type", sa.String(16), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_row_ref", sa.String(128), nullable=False),
    )
    for col in ("batch_id", "ip", "mac", "hostname"):
        op.create_index(f"ix_address_record_{col}", "address_record", [col])

    op.create_table(
        "endpoint_mapping",
        sa.Column("id", BigId, primary_key=True, autoincrement=True),
        sa.Column("flow_batch_id", sa.String(36), sa.ForeignKey("import_batch.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("endpoint_class", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("vm_id", sa.String(36), sa.ForeignKey("vm_inventory.id", ondelete="SET NULL"), nullable=True),
        sa.Column("method", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("candidate_vm_ids", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket_count", sa.Integer(), nullable=False),
        sa.Column("flow_count", sa.BigInteger(), nullable=False),
        sa.Column("resolver_version", sa.String(32), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
    )
    for col in ("flow_batch_id", "ip", "status", "vm_id"):
        op.create_index(f"ix_endpoint_mapping_{col}", "endpoint_mapping", [col])


def downgrade() -> None:
    op.drop_table("endpoint_mapping")
    op.drop_table("address_record")
    op.drop_table("flow_observation")
    op.drop_table("import_rejected_row")
