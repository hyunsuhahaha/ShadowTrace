"""Store evidence-backed graph path snapshots in reports."""
from alembic import op
import sqlalchemy as sa

revision = "0051_report_graph_paths"
down_revision = "0050_runbook_activity_handoffs"
branch_labels = None
depends_on = None


def upgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns("reports")}
    if "graph_path_snapshots" not in columns:
        op.add_column("reports", sa.Column("graph_path_snapshots", sa.Text(),
                                            nullable=False, server_default="[]"))


def downgrade():
    op.drop_column("reports", "graph_path_snapshots")
