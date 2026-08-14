"""Let a session/hash-crack job be explicitly parented under a specific
graph node (e.g. the finding it was launched from) instead of always
falling back to sync_from_project()'s generic host/service placement."""
from alembic import op
import sqlalchemy as sa


revision = "0037_graph_parent_node_id"
down_revision = "0036_notes"
branch_labels = None
depends_on = None

TABLES = ("interactive_sessions", "hash_crack_jobs")


def upgrade():
    for table in TABLES:
        existing = {row[1] for row in op.get_bind().exec_driver_sql(
            f"PRAGMA table_info({table})")}
        if "graph_parent_node_id" in existing:
            continue
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column(
                "graph_parent_node_id", sa.String(length=26), nullable=True))


def downgrade():
    for table in TABLES:
        with op.batch_alter_table(table) as batch:
            batch.drop_column("graph_parent_node_id")
