"""Link recorded HTTP exchanges to Runbook steps."""
from alembic import op
import sqlalchemy as sa

revision = "0049_runbook_http_exchanges"
down_revision = "0048_project_roe"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if "runbook_step_http_exchanges" not in sa.inspect(connection).get_table_names():
        op.create_table(
            "runbook_step_http_exchanges",
            sa.Column("step_id", sa.Integer(), sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
            sa.Column("exchange_id", sa.Integer(), sa.ForeignKey("http_exchanges.id"), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade():
    op.drop_table("runbook_step_http_exchanges")
