"""Add graph tracker tables (nodes, edges, per-project meta)."""
from alembic import op
import sqlalchemy as sa

revision = "0031_graph_tracker"
down_revision = "0030_hash_crack_attack_mode"
branch_labels = None
depends_on = None


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "graph_nodes" not in tables:
        op.create_table("graph_nodes",
            sa.Column("id", sa.String(26), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("type", sa.String(20), nullable=False),
            sa.Column("label", sa.String(300), nullable=False, server_default=""),
            sa.Column("status", sa.String(20), nullable=False, server_default="untried"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("source_ref", sa.Text(), nullable=False, server_default=""),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("tags", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("pinned", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("position", sa.Text(), nullable=False, server_default=""),
            sa.Column("meta", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("pinned_canonical_edge_id", sa.String(26), nullable=True))
        op.create_index("ix_graph_nodes_project_id", "graph_nodes", ["project_id"])
    if "graph_edges" not in tables:
        op.create_table("graph_edges",
            sa.Column("id", sa.String(26), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("source", sa.String(26), sa.ForeignKey("graph_nodes.id"), nullable=False),
            sa.Column("target", sa.String(26), sa.ForeignKey("graph_nodes.id"), nullable=False),
            sa.Column("relation", sa.String(30), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="untried"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("label", sa.String(300), nullable=False, server_default=""),
            sa.Column("meta", sa.Text(), nullable=False, server_default="{}"))
        op.create_index("ix_graph_edges_project_id", "graph_edges", ["project_id"])
        op.create_index("ix_graph_edges_source", "graph_edges", ["source"])
        op.create_index("ix_graph_edges_target", "graph_edges", ["target"])
    if "graph_project_meta" not in tables:
        op.create_table("graph_project_meta",
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), primary_key=True),
            sa.Column("root_node_id", sa.String(26), nullable=True),
            sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("layout", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    op.drop_table("graph_project_meta")
    op.drop_index("ix_graph_edges_target", table_name="graph_edges")
    op.drop_index("ix_graph_edges_source", table_name="graph_edges")
    op.drop_index("ix_graph_edges_project_id", table_name="graph_edges")
    op.drop_table("graph_edges")
    op.drop_index("ix_graph_nodes_project_id", table_name="graph_nodes")
    op.drop_table("graph_nodes")
