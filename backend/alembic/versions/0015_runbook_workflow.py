"""Add runbook conditions, credentials, observations, and findings."""
from alembic import op
import sqlalchemy as sa

revision = "0015_runbook_workflow"
down_revision = "0014_runbooks"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("runbook_step_templates",
                  sa.Column("condition", sa.Text(), nullable=False, server_default="{}"))
    op.add_column("runbook_step_instances",
                  sa.Column("condition", sa.Text(), nullable=False, server_default="{}"))
    op.create_table(
        "credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("username", sa.String(200), nullable=False),
        sa.Column("secret_kind", sa.String(30), nullable=False),
        sa.Column("secret_hint", sa.String(200), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("service_names", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_credentials_project_id", "credentials", ["project_id"])
    op.create_table(
        "runbook_step_credentials",
        sa.Column("step_id", sa.Integer(),
                  sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
        sa.Column("credential_id", sa.Integer(),
                  sa.ForeignKey("credentials.id"), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "runbook_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("step_id", sa.Integer(),
                  sa.ForeignKey("runbook_step_instances.id"), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id"), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_runbook_observations_step_id", "runbook_observations", ["step_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("observation_id", sa.Integer(),
                  sa.ForeignKey("runbook_observations.id"), nullable=False, unique=True),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_findings_project_id", "findings", ["project_id"])


def downgrade():
    op.drop_table("findings")
    op.drop_table("runbook_observations")
    op.drop_table("runbook_step_credentials")
    op.drop_table("credentials")
    op.drop_column("runbook_step_instances", "condition")
    op.drop_column("runbook_step_templates", "condition")
