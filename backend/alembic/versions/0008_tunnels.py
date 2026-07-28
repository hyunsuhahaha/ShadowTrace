"""Add user-configured SSH tunnel lifecycle records."""
from alembic import op
import sqlalchemy as sa

revision = "0008_tunnels"
down_revision = "0007_directory_information"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("tunnels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("ssh_host", sa.String(253), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(160), nullable=False),
        sa.Column("bind_host", sa.String(45), nullable=False),
        sa.Column("local_port", sa.Integer(), nullable=False),
        sa.Column("remote_host", sa.String(253), nullable=False),
        sa.Column("remote_port", sa.Integer(), nullable=True),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("log_path", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_table("tunnels")
