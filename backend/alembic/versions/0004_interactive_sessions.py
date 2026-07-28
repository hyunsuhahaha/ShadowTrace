"""Add PTY interactive session audit records."""
from alembic import op
import sqlalchemy as sa

revision = "0004_interactive_sessions"
down_revision = "0003_enumeration_workspace"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("interactive_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("template_id", sa.String(100), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("cwd", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("log_path", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False))


def downgrade():
    op.drop_table("interactive_sessions")
