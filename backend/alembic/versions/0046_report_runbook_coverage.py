"""Allow reports to select Runbook instances for coverage summaries."""
from alembic import op
import sqlalchemy as sa


revision = "0046_report_runbook_coverage"
down_revision = "0045_session_reconstruction"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("reports") as batch:
        batch.add_column(sa.Column("runbook_instance_links", sa.Text(),
                                   nullable=False, server_default="[]"))


def downgrade():
    with op.batch_alter_table("reports") as batch:
        batch.drop_column("runbook_instance_links")
