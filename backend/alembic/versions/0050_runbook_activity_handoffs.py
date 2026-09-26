"""Link remote activity and evidence-backed cross-target handoffs to Runbooks."""
from alembic import op
import sqlalchemy as sa

revision = "0050_runbook_activity_handoffs"
down_revision = "0049_runbook_http_exchanges"
branch_labels = None
depends_on = None


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "runbook_step_remote_executions" not in tables:
        op.create_table("runbook_step_remote_executions",
            sa.Column("step_id", sa.Integer(), sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
            sa.Column("remote_execution_id", sa.Integer(), sa.ForeignKey("remote_executions.id"), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    if "runbook_step_sessions" not in tables:
        op.create_table("runbook_step_sessions",
            sa.Column("step_id", sa.Integer(), sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
            sa.Column("session_id", sa.Integer(), sa.ForeignKey("interactive_sessions.id"), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    if "runbook_step_handoffs" not in tables:
        op.create_table("runbook_step_handoffs",
            sa.Column("from_step_id", sa.Integer(), sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
            sa.Column("to_step_id", sa.Integer(), sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
            sa.Column("remote_execution_id", sa.Integer(), sa.ForeignKey("remote_executions.id"), nullable=False),
            sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id"), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    op.drop_table("runbook_step_handoffs")
    op.drop_table("runbook_step_sessions")
    op.drop_table("runbook_step_remote_executions")
