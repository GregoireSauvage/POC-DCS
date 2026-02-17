"""add perf_logs source column

Revision ID: 20260216_add_perf_source
Revises: 
Create Date: 2026-02-16
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20260216_add_perf_source"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "perf_logs",
        sa.Column("source", sa.Text(), nullable=True, server_default="unknown"),
    )


def downgrade() -> None:
    op.drop_column("perf_logs", "source")
