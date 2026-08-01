"""Add finding-centered reporting."""
from alembic import op
import sqlalchemy as sa

revision = "0018_findings"
down_revision = "0017_builtin_runbooks"
branch_labels = None
depends_on = None

def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "finding_templates" not in tables:
      op.create_table("finding_templates",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("title", sa.String(200), nullable=False),
        sa.Column("category", sa.String(120), nullable=False), sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_vector", sa.String(160), nullable=False), sa.Column("description", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False), sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("references", sa.Text(), nullable=False), sa.Column("cwe", sa.String(80), nullable=False),
        sa.Column("cve", sa.String(80), nullable=False), sa.Column("mitre_attack", sa.Text(), nullable=False),
        sa.Column("tags", sa.Text(), nullable=False), sa.Column("use_count", sa.Integer(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True), sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False))
    columns = (
        sa.Column("template_id", sa.Integer(), nullable=True),
        sa.Column("category", sa.String(120), nullable=False, server_default=""),
        sa.Column("severity", sa.String(20), nullable=False, server_default="Informational"),
        sa.Column("cvss_version", sa.String(10), nullable=False, server_default="3.1"),
        sa.Column("cvss_vector", sa.String(160), nullable=False, server_default=""),
        sa.Column("cvss_score", sa.String(8), nullable=False, server_default="0.0"),
        sa.Column("final_risk", sa.String(20), nullable=False, server_default="Informational"),
        sa.Column("risk_override_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("business_impact", sa.Text(), nullable=False, server_default=""),
        sa.Column("technical_impact", sa.Text(), nullable=False, server_default=""),
        sa.Column("reproduction_steps", sa.Text(), nullable=False, server_default=""),
        sa.Column("recommendation", sa.Text(), nullable=False, server_default=""),
        sa.Column("references", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("tags", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("discovered_at", sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("retested_at", sa.DateTime(), nullable=True),
        sa.Column("retest_result", sa.Text(), nullable=False, server_default=""),
        sa.Column("disclosure", sa.String(10), nullable=False, server_default="BOTH"),
        sa.Column("internal_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("sort_priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("template_snapshot", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.current_timestamp()),
    )
    existing = {item["name"] for item in inspector.get_columns("findings")}
    for column in columns:
        if column.name not in existing:
            op.add_column("findings", column)
    op.create_index("ix_findings_project", "findings", ["project_id"])
    if "finding_evidence" not in tables:
      op.create_table("finding_evidence",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True),
        sa.Column("caption", sa.Text(), nullable=False), sa.Column("display_order", sa.Integer(), nullable=False),
        sa.Column("include_client", sa.Boolean(), nullable=False), sa.Column("include_internal", sa.Boolean(), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False), sa.Column("phase", sa.String(10), nullable=False))
    if "finding_retests" not in tables:
      op.create_table("finding_retests",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tested_at", sa.DateTime(), nullable=False), sa.Column("tester", sa.String(160), nullable=False),
        sa.Column("result", sa.String(40), nullable=False), sa.Column("remediated", sa.Boolean(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False), sa.Column("before_evidence_ids", sa.Text(), nullable=False),
        sa.Column("after_evidence_ids", sa.Text(), nullable=False))
    if "evidence_image_edits" not in tables:
      op.create_table("evidence_image_edits",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False), sa.Column("operations", sa.Text(), nullable=False),
        sa.Column("original_sha256", sa.String(64), nullable=False), sa.Column("rendered_path", sa.Text(), nullable=False),
        sa.Column("rendered_sha256", sa.String(64), nullable=False), sa.Column("caption", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False))
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("evidence_image_edits")}
    if "uq_evidence_edit_version" not in indexes:
        op.create_index("uq_evidence_edit_version", "evidence_image_edits", ["evidence_id", "version"], unique=True)

def downgrade():
    op.drop_index("uq_evidence_edit_version", table_name="evidence_image_edits")
    for table in ("evidence_image_edits", "finding_retests", "finding_evidence", "finding_templates"):
        op.drop_table(table)
    for name in ("template_id", "category", "severity", "cvss_version", "cvss_vector",
                 "cvss_score", "final_risk", "risk_override_reason", "summary",
                 "business_impact", "technical_impact", "reproduction_steps",
                 "recommendation", "references", "tags", "discovered_at", "retested_at",
                 "retest_result", "disclosure", "internal_notes", "sort_priority",
                 "template_snapshot", "updated_at"):
        op.drop_column("findings", name)
