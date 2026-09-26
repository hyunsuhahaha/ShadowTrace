"""Store typed components within web, mobile, cloud, source and OT assets."""
from alembic import op
import sqlalchemy as sa

revision = "0052_assessment_asset_subjects"
down_revision = "0051_report_graph_paths"
branch_labels = None
depends_on = None


def upgrade():
    if "assessment_asset_subjects" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table("assessment_asset_subjects",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assessment_assets.id"), nullable=False),
            sa.Column("kind", sa.String(40), nullable=False),
            sa.Column("label", sa.String(200), nullable=False),
            sa.Column("identifier", sa.String(500), nullable=False),
            sa.Column("attributes", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("scope_status", sa.String(24), nullable=False, server_default="pending"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("asset_id", "kind", "identifier", name="uq_assessment_subject_identity"))
        op.create_index("ix_assessment_asset_subjects_asset_id", "assessment_asset_subjects", ["asset_id"])


def downgrade():
    op.drop_index("ix_assessment_asset_subjects_asset_id", table_name="assessment_asset_subjects")
    op.drop_table("assessment_asset_subjects")
