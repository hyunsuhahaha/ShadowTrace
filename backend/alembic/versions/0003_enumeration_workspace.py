"""Add service workspace and execution lifecycle metadata."""
from alembic import op
import sqlalchemy as sa

revision = "0003_enumeration_workspace"
down_revision = "0002_scan_job_metadata"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("services", sa.Column(
        "notes", sa.Text(), nullable=False, server_default=""))
    op.add_column("services", sa.Column(
        "tags", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("executions", sa.Column(
        "status", sa.String(20), nullable=False, server_default="queued"))
    op.add_column("executions", sa.Column(
        "error", sa.Text(), nullable=False, server_default=""))
    op.add_column("executions", sa.Column(
        "output_path", sa.Text(), nullable=False, server_default=""))


def downgrade():
    for column in ("output_path", "error", "status"):
        op.drop_column("executions", column)
    for column in ("tags", "notes"):
        op.drop_column("services", column)
