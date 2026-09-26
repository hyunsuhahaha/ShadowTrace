"""Link typed asset subjects to the Runbook checks that assessed them."""
from alembic import op
import sqlalchemy as sa

revision = "0053_runbook_step_subjects"
down_revision = "0052_assessment_asset_subjects"
branch_labels = None
depends_on = None


def upgrade():
    if "runbook_step_subjects" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table("runbook_step_subjects",
            sa.Column("step_id", sa.Integer(), sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
            sa.Column("subject_id", sa.Integer(), sa.ForeignKey("assessment_asset_subjects.id"), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    op.drop_table("runbook_step_subjects")
