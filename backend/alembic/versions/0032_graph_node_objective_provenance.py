"""Add objective/provenance/layer fields to graph_nodes."""
from alembic import op
import sqlalchemy as sa

revision = "0032_graph_node_objective_provenance"
down_revision = "0031_graph_tracker"
branch_labels = None
depends_on = None


def upgrade():
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("graph_nodes")}
    additions = [
        ("objective", sa.Column("objective", sa.Boolean(), nullable=False,
                                server_default=sa.false())),
        ("objective_kind", sa.Column("objective_kind", sa.String(20), nullable=True)),
        ("provenance", sa.Column("provenance", sa.Text(), nullable=False,
                                 server_default="")),
        ("layer", sa.Column("layer", sa.Integer(), nullable=True)),
    ]
    for name, column in additions:
        if name not in columns:
            op.add_column("graph_nodes", column)


def downgrade():
    for name in ("layer", "provenance", "objective_kind", "objective"):
        op.drop_column("graph_nodes", name)
