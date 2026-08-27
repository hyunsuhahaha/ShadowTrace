"""Add passive activity records linked to normalized scan jobs."""
from alembic import op
import sqlalchemy as sa


revision = "0043_passive_activities"
down_revision = "0042_autorecon_runs"
branch_labels = None
depends_on = None


def upgrade():
    existing = op.get_bind().exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).scalars().all()
    if "passive_activities" in existing:
        return
    op.create_table(
        "passive_activities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("process_key", sa.String(160), nullable=False, unique=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("tool", sa.String(80), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("argv", sa.Text(), nullable=False),
        sa.Column("cwd", sa.Text(), nullable=False),
        sa.Column("tty", sa.String(160), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("ppid", sa.Integer(), nullable=True),
        sa.Column("uid", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("output_path", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("parser", sa.String(80), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    existing = op.get_bind().exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).scalars().all()
    if "passive_activities" in existing:
        op.drop_table("passive_activities")
