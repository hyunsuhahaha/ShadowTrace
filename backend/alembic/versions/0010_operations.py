"""Add local mutation audit events."""
from alembic import op
import sqlalchemy as sa

revision = "0010_operations"
down_revision = "0009_reports"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("method", sa.String(12), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False))


def downgrade():
    op.drop_table("audit_events")
