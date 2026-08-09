"""Add hidden flag to graph_nodes (user-dismissed clutter)."""
from alembic import op
import sqlalchemy as sa

revision = "0033_graph_node_hidden"
down_revision = "0032_graph_node_objective_provenance"
branch_labels = None
depends_on = None


def upgrade():
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("graph_nodes")}
    if "hidden" not in columns:
        op.add_column("graph_nodes", sa.Column(
            "hidden", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("graph_nodes", "hidden")
