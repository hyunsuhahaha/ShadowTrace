"""Add user-managed scan metadata."""
from alembic import op
import sqlalchemy as sa

revision = "0002_scan_job_metadata"
down_revision = "0001_scan_center"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scan_jobs", sa.Column(
        "alias", sa.String(120), nullable=False, server_default=""))
    op.add_column("scan_jobs", sa.Column(
        "tags", sa.Text(), nullable=False, server_default="[]"))


def downgrade():
    op.drop_column("scan_jobs", "tags")
    op.drop_column("scan_jobs", "alias")
