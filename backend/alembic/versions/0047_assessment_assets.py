"""Add non-IP assessment assets and allow a Runbook to target one."""
from alembic import op
import sqlalchemy as sa


revision = "0047_assessment_assets"
down_revision = "0046_report_runbook_coverage"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    if "assessment_assets" not in inspector.get_table_names():
        op.create_table(
            "assessment_assets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("kind", sa.String(32), nullable=False),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("locator", sa.String(500), nullable=False, server_default=""),
            sa.Column("details", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("scope_status", sa.String(24), nullable=False, server_default="pending"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "ix_assessment_assets_project_id" not in {
            item["name"] for item in sa.inspect(connection).get_indexes("assessment_assets")}:
        op.create_index("ix_assessment_assets_project_id", "assessment_assets", ["project_id"])
    for table in ("runbook_instances", "evidence", "findings"):
        columns = {item["name"]: item for item in sa.inspect(connection).get_columns(table)}
        needs_nullable_target = (table != "findings" and not columns["target_id"]["nullable"])
        needs_asset = "asset_id" not in columns
        if not needs_nullable_target and not needs_asset:
            continue
        with op.batch_alter_table(table) as batch:
            if needs_nullable_target:
                batch.alter_column("target_id", existing_type=sa.Integer(), nullable=True)
            if needs_asset:
                batch.add_column(sa.Column("asset_id", sa.Integer(), nullable=True))
                batch.create_foreign_key(f"fk_{table}_asset_id", "assessment_assets",
                                         ["asset_id"], ["id"])


def downgrade():
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("asset_id")
    with op.batch_alter_table("evidence") as batch:
        batch.drop_column("asset_id")
        batch.alter_column("target_id", existing_type=sa.Integer(), nullable=False)
    with op.batch_alter_table("runbook_instances") as batch:
        batch.drop_column("asset_id")
        batch.alter_column("target_id", existing_type=sa.Integer(), nullable=False)
    op.drop_index("ix_assessment_assets_project_id", table_name="assessment_assets")
    op.drop_table("assessment_assets")
