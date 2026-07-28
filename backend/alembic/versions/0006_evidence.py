"""Add evidence records and file provenance."""
from alembic import op
import sqlalchemy as sa

revision = "0006_evidence"
down_revision = "0005_web_testing"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("source_type", sa.String(40), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("original_name", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("acquired_at", sa.DateTime(), nullable=False),
        sa.Column("username", sa.String(160), nullable=False),
        sa.Column("hostname", sa.String(253), nullable=False),
        sa.Column("privilege", sa.String(80), nullable=False),
        sa.Column("sensitivity", sa.String(20), nullable=False),
        sa.Column("include_report", sa.Boolean(), nullable=False),
        sa.Column("tags", sa.Text(), nullable=False),
        sa.Column("markdown", sa.Text(), nullable=False),
        sa.Column("duplicate_of", sa.Integer(), sa.ForeignKey("evidence.id"), nullable=True))


def downgrade():
    op.drop_table("evidence")
