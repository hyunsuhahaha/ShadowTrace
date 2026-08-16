"""Track which ScanJob (if any) launched an execution, so AutoRecon's
service-fan-out can be queried precisely via
GET /api/scans/{scan_job_id}/service-executions instead of guessing from
timestamps."""
from alembic import op
import sqlalchemy as sa


revision = "0041_execution_scan_job"
down_revision = "0040_execution_graph_hidden"
branch_labels = None
depends_on = None


def upgrade():
    existing = {row[1] for row in op.get_bind().exec_driver_sql(
        "PRAGMA table_info(executions)")}
    if "scan_job_id" in existing:
        return
    # No named FK constraint here (SQLite's batch ALTER requires naming it,
    # and this codebase doesn't do that for other later-added FK columns
    # either) -- SQLite doesn't enforce FKs by default, and the ORM model's
    # ForeignKey("scan_jobs.id") already documents/enforces the relationship
    # at the SQLAlchemy layer.
    with op.batch_alter_table("executions") as batch:
        batch.add_column(sa.Column("scan_job_id", sa.Integer(), nullable=True))


def downgrade():
    with op.batch_alter_table("executions") as batch:
        batch.drop_column("scan_job_id")
