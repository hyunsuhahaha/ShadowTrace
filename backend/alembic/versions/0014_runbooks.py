"""Add the runbook/checklist engine foundation."""
from alembic import op
import sqlalchemy as sa

revision = "0014_runbooks"
down_revision = "0013_exploit_local_runs"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "runbook_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("tags", sa.Text(), nullable=False),
        sa.Column("service_names", sa.Text(), nullable=False),
        sa.Column("ports", sa.Text(), nullable=False),
        sa.Column("origin", sa.String(20), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "runbook_template_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("template_id", sa.Integer(),
                  sa.ForeignKey("runbook_templates.id"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("tags", sa.Text(), nullable=False),
        sa.Column("service_names", sa.Text(), nullable=False),
        sa.Column("ports", sa.Text(), nullable=False),
        sa.Column("published_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("template_id", "version",
                            name="uq_runbook_template_version"),
    )
    op.create_table(
        "runbook_step_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("version_id", sa.Integer(),
                  sa.ForeignKey("runbook_template_versions.id"), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("command_refs", sa.Text(), nullable=False),
        sa.Column("expected_observations", sa.Text(), nullable=False),
        sa.UniqueConstraint("version_id", "position",
                            name="uq_runbook_step_position"),
    )
    op.create_table(
        "runbook_instances",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("version_id", sa.Integer(),
                  sa.ForeignKey("runbook_template_versions.id"), nullable=False),
        sa.Column("template_name", sa.String(160), nullable=False),
        sa.Column("target_name", sa.String(120), nullable=False),
        sa.Column("service_name", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("target_id", "service_id", "version_id",
                            name="uq_runbook_instance_scope"),
    )
    op.create_table(
        "runbook_step_instances",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("instance_id", sa.Integer(),
                  sa.ForeignKey("runbook_instances.id"), nullable=False),
        sa.Column("source_step_id", sa.Integer(),
                  sa.ForeignKey("runbook_step_templates.id"), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("command_refs", sa.Text(), nullable=False),
        sa.Column("expected_observations", sa.Text(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("result", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("status_reason", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("instance_id", "position",
                            name="uq_runbook_instance_step_position"),
    )
    op.create_table(
        "runbook_step_evidence",
        sa.Column("step_id", sa.Integer(),
                  sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id"),
                  primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "runbook_step_executions",
        sa.Column("step_id", sa.Integer(),
                  sa.ForeignKey("runbook_step_instances.id"), primary_key=True),
        sa.Column("execution_id", sa.Integer(), sa.ForeignKey("executions.id"),
                  primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "runbook_activity_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("instance_id", sa.Integer(),
                  sa.ForeignKey("runbook_instances.id"), nullable=False),
        sa.Column("step_id", sa.Integer(),
                  sa.ForeignKey("runbook_step_instances.id"), nullable=True),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
    )
    for table, column in (
        ("runbook_template_versions", "template_id"),
        ("runbook_step_templates", "version_id"),
        ("runbook_instances", "project_id"),
        ("runbook_instances", "target_id"),
        ("runbook_instances", "service_id"),
        ("runbook_step_instances", "instance_id"),
        ("runbook_activity_events", "instance_id"),
    ):
        op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade():
    for table in (
        "runbook_activity_events", "runbook_step_executions",
        "runbook_step_evidence", "runbook_step_instances", "runbook_instances",
        "runbook_step_templates", "runbook_template_versions", "runbook_templates",
    ):
        op.drop_table(table)
