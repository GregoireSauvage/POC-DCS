"""add resource bindings

Revision ID: 20260317_add_resource_bindings
Revises: 20260317_add_audit_policy_metadata
Create Date: 2026-03-17
"""

import sqlalchemy as sa

from alembic import op

revision = "20260317_add_resource_bindings"
down_revision = "20260317_add_audit_policy_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "resource_bindings",
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.UUID(), nullable=False),
        sa.Column("label_payload", sa.JSON(), nullable=False),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("label_hash", sa.Text(), nullable=False),
        sa.Column("proof", sa.Text(), nullable=False),
        sa.Column("proof_algorithm", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "resource_type IN ('film','hall','spectator')",
            name="ck_resource_bindings_resource_type",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "resource_type", "resource_id"),
    )
    op.create_index(
        "idx_resource_bindings_resource",
        "resource_bindings",
        ["tenant_id", "resource_type"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("idx_resource_bindings_resource", table_name="resource_bindings")
    op.drop_table("resource_bindings")
