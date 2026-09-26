"""Versioned project Rules of Engagement with an approval audit trail."""
from alembic import op
import sqlalchemy as sa

revision = "0048_project_roe"
down_revision = "0047_assessment_assets"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    tables = set(sa.inspect(connection).get_table_names())
    if "project_roe" not in tables:
        op.create_table(
            "project_roe",
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), primary_key=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
            sa.Column("included_targets", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("excluded_targets", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("asset_ids", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("allowed_actions", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
            sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("approved_by", sa.String(160), nullable=False, server_default=""),
            sa.Column("approval_reason", sa.Text(), nullable=False, server_default=""),
            sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "project_roe_events" not in tables:
        op.create_table(
            "project_roe_events",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("action", sa.String(24), nullable=False),
            sa.Column("actor", sa.String(160), nullable=False),
            sa.Column("snapshot", sa.Text(), nullable=False),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "ix_project_roe_events_project_id" not in {
            item["name"] for item in sa.inspect(connection).get_indexes("project_roe_events")}:
        op.create_index("ix_project_roe_events_project_id", "project_roe_events", ["project_id"])
    connection.execute(sa.text(
        "INSERT INTO project_roe (project_id,status,included_targets,excluded_targets,"
        "asset_ids,allowed_actions,notes,approved_by,approval_reason,revision,updated_at) "
        "SELECT id,'draft','[]','[]','[]','[]','','','',1,CURRENT_TIMESTAMP "
        "FROM projects WHERE id NOT IN (SELECT project_id FROM project_roe)"))


def downgrade():
    op.drop_index("ix_project_roe_events_project_id", table_name="project_roe_events")
    op.drop_table("project_roe_events")
    op.drop_table("project_roe")
