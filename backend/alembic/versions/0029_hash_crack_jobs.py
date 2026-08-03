"""Add hash_crack_jobs for the offline hashcat cracking workflow."""
from alembic import op
import sqlalchemy as sa

revision = "0029_hash_crack_jobs"
down_revision = "0028_post_exploitation"
branch_labels = None
depends_on = None


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "hash_crack_jobs" in tables:
        return
    op.create_table("hash_crack_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("label", sa.String(200), nullable=False, server_default=""),
        sa.Column("hash_mode_id", sa.String(40), nullable=False),
        sa.Column("hash_mode", sa.String(20), nullable=False),
        sa.Column("hash_type_name", sa.String(120), nullable=False, server_default=""),
        sa.Column("wordlist_id", sa.String(80), nullable=False, server_default=""),
        sa.Column("rule_id", sa.String(80), nullable=False, server_default=""),
        sa.Column("hash_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("argv_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("command_display", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="prepared"),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("cracked_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cancelled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()))
    op.create_index("ix_hash_crack_jobs_status", "hash_crack_jobs", ["status"])


def downgrade():
    op.drop_index("ix_hash_crack_jobs_status", table_name="hash_crack_jobs")
    op.drop_table("hash_crack_jobs")
