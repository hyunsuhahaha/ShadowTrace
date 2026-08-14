"""Let a hash-crack job pick its cracking engine (hashcat or john)."""
from alembic import op
import sqlalchemy as sa


revision = "0038_hash_crack_engine"
down_revision = "0037_graph_parent_node_id"
branch_labels = None
depends_on = None


def upgrade():
    existing = {row[1] for row in op.get_bind().exec_driver_sql(
        "PRAGMA table_info(hash_crack_jobs)")}
    if "engine" in existing:
        return
    with op.batch_alter_table("hash_crack_jobs") as batch:
        batch.add_column(sa.Column(
            "engine", sa.String(length=10), nullable=False, server_default="hashcat"))


def downgrade():
    with op.batch_alter_table("hash_crack_jobs") as batch:
        batch.drop_column("engine")
