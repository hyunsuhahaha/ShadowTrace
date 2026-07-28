"""Add user-authored HTTP requests and response history."""
from alembic import op
import sqlalchemy as sa

revision = "0005_web_testing"
down_revision = "0004_interactive_sessions"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("http_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("folder", sa.String(160), nullable=False),
        sa.Column("tags", sa.Text(), nullable=False),
        sa.Column("method", sa.String(12), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("headers", sa.Text(), nullable=False),
        sa.Column("cookies", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("body_mode", sa.String(20), nullable=False),
        sa.Column("tls_verify", sa.Boolean(), nullable=False),
        sa.Column("proxy", sa.Text(), nullable=False),
        sa.Column("timeout", sa.Integer(), nullable=False),
        sa.Column("follow_redirects", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False))
    op.create_table("http_exchanges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("request_id", sa.Integer(), sa.ForeignKey("http_requests.id"), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("request_snapshot", sa.Text(), nullable=False),
        sa.Column("response_headers", sa.Text(), nullable=False),
        sa.Column("response_cookies", sa.Text(), nullable=False),
        sa.Column("response_body", sa.LargeBinary(), nullable=False),
        sa.Column("body_path", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False))


def downgrade():
    op.drop_table("http_exchanges")
    op.drop_table("http_requests")
