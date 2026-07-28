"""Add user-authored reports and evidence links."""
from alembic import op
import sqlalchemy as sa

revision = "0009_reports"
down_revision = "0008_tunnels"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("template", sa.String(40), nullable=False),
        sa.Column("markdown", sa.Text(), nullable=False),
        sa.Column("evidence_links", sa.Text(), nullable=False),
        sa.Column("sensitivity_reviewed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False))


def downgrade():
    op.drop_table("reports")
