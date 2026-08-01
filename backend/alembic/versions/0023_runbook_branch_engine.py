"""Add executable branching state to runbooks."""
from alembic import op
import sqlalchemy as sa


revision = "0023_runbook_branch_engine"
down_revision = "0022_service_intelligence"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("runbook_step_templates") as batch:
        batch.add_column(sa.Column("node_key", sa.String(120), nullable=False,
                                   server_default=""))
        batch.add_column(sa.Column("node_type", sa.String(32), nullable=False,
                                   server_default="manual_check"))
        batch.add_column(sa.Column("transitions", sa.Text(), nullable=False,
                                   server_default="[]"))
        batch.add_column(sa.Column("error_policy", sa.Text(), nullable=False,
                                   server_default="{}"))
        batch.add_column(sa.Column("approval", sa.Text(), nullable=False,
                                   server_default="{}"))
    with op.batch_alter_table("runbook_step_instances") as batch:
        batch.add_column(sa.Column("node_key", sa.String(120), nullable=False,
                                   server_default=""))
        batch.add_column(sa.Column("node_type", sa.String(32), nullable=False,
                                   server_default="manual_check"))
        batch.add_column(sa.Column("transitions", sa.Text(), nullable=False,
                                   server_default="[]"))
        batch.add_column(sa.Column("error_policy", sa.Text(), nullable=False,
                                   server_default="{}"))
        batch.add_column(sa.Column("approval", sa.Text(), nullable=False,
                                   server_default="{}"))
        batch.add_column(sa.Column("activation", sa.String(24), nullable=False,
                                   server_default="waiting"))
        batch.add_column(sa.Column("decision_trace", sa.Text(), nullable=False,
                                   server_default="[]"))
        batch.add_column(sa.Column("approval_status", sa.String(24), nullable=False,
                                   server_default="not_required"))
        batch.add_column(sa.Column("approval_reason", sa.Text(), nullable=False,
                                   server_default=""))
        batch.add_column(sa.Column("approved_by", sa.String(160), nullable=False,
                                   server_default=""))
        batch.add_column(sa.Column("attempts", sa.Integer(), nullable=False,
                                   server_default="0"))
        batch.add_column(sa.Column("last_error", sa.Text(), nullable=False,
                                   server_default=""))
    op.create_index("ix_runbook_step_instances_activation",
                    "runbook_step_instances", ["instance_id", "activation"])


def downgrade():
    op.drop_index("ix_runbook_step_instances_activation",
                  table_name="runbook_step_instances")
    with op.batch_alter_table("runbook_step_instances") as batch:
        for column in (
            "last_error", "attempts", "approved_by", "approval_reason",
            "approval_status", "decision_trace", "activation", "approval",
            "error_policy", "transitions", "node_type", "node_key",
        ):
            batch.drop_column(column)
    with op.batch_alter_table("runbook_step_templates") as batch:
        for column in ("approval", "error_policy", "transitions",
                       "node_type", "node_key"):
            batch.drop_column(column)
