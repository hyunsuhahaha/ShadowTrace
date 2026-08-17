"""Pivot AutoRecon from a native catalog-tag fan-out (0041's
executions.scan_job_id) to wrapping the real `autorecon` (Tib3rius) binary:
drop the now-unused column and add autorecon_runs, which tracks one
subprocess invocation against one or more targets at once (distinct from
ScanJob, which is always exactly one target per row)."""
from alembic import op
import sqlalchemy as sa


revision = "0042_autorecon_runs"
down_revision = "0041_execution_scan_job"
branch_labels = None
depends_on = None


def upgrade():
    existing = {row[1] for row in op.get_bind().exec_driver_sql(
        "PRAGMA table_info(executions)")}
    if "scan_job_id" in existing:
        with op.batch_alter_table("executions") as batch:
            batch.drop_column("scan_job_id")
    if "autorecon_runs" not in op.get_bind().exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'").scalars().all():
        op.create_table("autorecon_runs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("target_ids", sa.Text(), nullable=False),
            sa.Column("command", sa.Text(), nullable=False),
            sa.Column("output_dir", sa.Text(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("exit_code", sa.Integer(), nullable=True),
            sa.Column("stopped", sa.Boolean(), nullable=False),
            sa.Column("error", sa.Text(), nullable=False),
            sa.Column("imported_count", sa.Integer(), nullable=False),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("ended_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    op.drop_table("autorecon_runs")
    with op.batch_alter_table("executions") as batch:
        batch.add_column(sa.Column("scan_job_id", sa.Integer(), nullable=True))
