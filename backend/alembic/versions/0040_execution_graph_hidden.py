"""Let an execution opt out of getting its own graph node when another
node's Inspector already renders its result inline (e.g. the
ftp-directory-tree crawl auto-fired alongside its ftp-client session)."""
from alembic import op
import sqlalchemy as sa


revision = "0040_execution_graph_hidden"
down_revision = "0039_execution_graph_parent"
branch_labels = None
depends_on = None


def upgrade():
    existing = {row[1] for row in op.get_bind().exec_driver_sql(
        "PRAGMA table_info(executions)")}
    if "graph_hidden" in existing:
        return
    with op.batch_alter_table("executions") as batch:
        batch.add_column(sa.Column(
            "graph_hidden", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    with op.batch_alter_table("executions") as batch:
        batch.drop_column("graph_hidden")
