"""Add append-only graph event snapshots for attack replay."""
from alembic import op
import sqlalchemy as sa

revision = "0034_graph_events"
down_revision = "0033_graph_node_hidden"
branch_labels = None
depends_on = None


def upgrade():
    if "graph_events" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "graph_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False, server_default="graph-snapshot"),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_graph_events_project_id", "graph_events", ["project_id"])
    op.create_index("ix_graph_events_fingerprint", "graph_events", ["fingerprint"])


def downgrade():
    op.drop_table("graph_events")
