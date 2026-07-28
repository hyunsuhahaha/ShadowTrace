"""Add persisted application settings."""
from alembic import op
import sqlalchemy as sa

revision = "0011_settings"
down_revision = "0010_operations"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("app_settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False))


def downgrade():
    op.drop_table("app_settings")
