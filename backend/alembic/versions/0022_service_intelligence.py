"""Add service detection evidence and structured runbook guidance."""
from alembic import op
import sqlalchemy as sa


revision = "0022_service_intelligence"
down_revision = "0021_finding_observation_nullable"
branch_labels = None
depends_on = None


def upgrade():
    for table in ("services", "service_observations"):
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("cpe", sa.Text(), nullable=False,
                                       server_default="[]"))
            batch.add_column(sa.Column("tls", sa.Boolean(), nullable=False,
                                       server_default=sa.false()))
            batch.add_column(sa.Column("detection_evidence", sa.Text(), nullable=False,
                                       server_default="{}"))
    with op.batch_alter_table("runbook_step_templates") as batch:
        batch.add_column(sa.Column("guidance", sa.Text(), nullable=False,
                                   server_default="{}"))
    with op.batch_alter_table("runbook_step_instances") as batch:
        batch.add_column(sa.Column("guidance", sa.Text(), nullable=False,
                                   server_default="{}"))
        batch.add_column(sa.Column("outcome", sa.String(length=24), nullable=False,
                                   server_default="unknown"))
        batch.add_column(sa.Column("assessment", sa.Text(), nullable=False,
                                   server_default="{}"))


def downgrade():
    with op.batch_alter_table("runbook_step_instances") as batch:
        batch.drop_column("assessment")
        batch.drop_column("outcome")
        batch.drop_column("guidance")
    with op.batch_alter_table("runbook_step_templates") as batch:
        batch.drop_column("guidance")
    for table in ("service_observations", "services"):
        with op.batch_alter_table(table) as batch:
            batch.drop_column("detection_evidence")
            batch.drop_column("tls")
            batch.drop_column("cpe")
