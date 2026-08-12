"""Add standalone Note table, independent of any single owning record."""
from alembic import op
import sqlalchemy as sa


revision = "0036_notes"
down_revision = "0035_credential_source_execution"
branch_labels = None
depends_on = None


def upgrade():
    if "notes" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("credential_id", sa.Integer(), sa.ForeignKey("credentials.id"), nullable=True),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("author", sa.String(160), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_notes_project_id", "notes", ["project_id"])


def downgrade():
    op.drop_table("notes")
