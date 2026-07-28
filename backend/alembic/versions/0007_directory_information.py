"""Add observed Active Directory information."""
from alembic import op
import sqlalchemy as sa

revision = "0007_directory_information"
down_revision = "0006_evidence"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("directory_objects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("attributes", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("tags", sa.Text(), nullable=False),
        sa.Column("source", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False))
    op.create_table("directory_relations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("directory_objects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("directory_objects.id"), nullable=False),
        sa.Column("relation", sa.String(100), nullable=False),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id"), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.DateTime(), nullable=False))


def downgrade():
    op.drop_table("directory_relations")
    op.drop_table("directory_objects")
