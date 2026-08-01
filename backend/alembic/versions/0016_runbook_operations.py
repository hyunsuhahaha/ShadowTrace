"""Add runbook timers and recommendation dismissal state."""
from alembic import op
import sqlalchemy as sa

revision = "0016_runbook_operations"
down_revision = "0015_runbook_workflow"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("runbook_step_instances",
                  sa.Column("timer_started_at", sa.DateTime(), nullable=True))
    op.add_column("runbook_step_instances",
                  sa.Column("elapsed_seconds", sa.Integer(), nullable=False,
                            server_default="0"))
    op.create_table(
        "runbook_recommendation_dismissals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("version_id", sa.Integer(),
                  sa.ForeignKey("runbook_template_versions.id"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("dismissed_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("service_id", "version_id", "fingerprint",
                            name="uq_runbook_recommendation_dismissal"),
    )
    op.create_index("ix_runbook_recommendation_dismissals_service",
                    "runbook_recommendation_dismissals", ["service_id"])


def downgrade():
    op.drop_table("runbook_recommendation_dismissals")
    op.drop_column("runbook_step_instances", "elapsed_seconds")
    op.drop_column("runbook_step_instances", "timer_started_at")
