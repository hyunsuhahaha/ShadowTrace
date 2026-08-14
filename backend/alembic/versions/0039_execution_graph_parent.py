"""Let an execution be explicitly parented under a specific graph node
(e.g. the finding it was run to follow up on) instead of always falling
back to sync_from_project()'s default host/service placement."""
from alembic import op
import sqlalchemy as sa


revision = "0039_execution_graph_parent"
down_revision = "0038_hash_crack_engine"
branch_labels = None
depends_on = None


def upgrade():
    existing = {row[1] for row in op.get_bind().exec_driver_sql(
        "PRAGMA table_info(executions)")}
    if "graph_parent_node_id" in existing:
        return
    with op.batch_alter_table("executions") as batch:
        batch.add_column(sa.Column(
            "graph_parent_node_id", sa.String(length=26), nullable=True))


def downgrade():
    with op.batch_alter_table("executions") as batch:
        batch.drop_column("graph_parent_node_id")
