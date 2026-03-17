"""add audit policy metadata

Revision ID: 20260317_add_audit_policy_metadata
Revises: 20260216_add_perf_source
Create Date: 2026-03-17
"""

import sqlalchemy as sa

from alembic import op

revision = "20260317_add_audit_policy_metadata"
down_revision = "20260216_add_perf_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("policy_id", sa.Text(), nullable=True))
    op.add_column("audit_logs", sa.Column("policy_version", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_logs", "policy_version")
    op.drop_column("audit_logs", "policy_id")
