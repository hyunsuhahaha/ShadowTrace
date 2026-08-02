"""Add review_status to http_exchanges so the Intruder review column persists."""
from alembic import op
import sqlalchemy as sa


revision = "0026_exchange_review_status"
down_revision = "0025_metasploit_lock"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    existing = {row[1] for row in bind.exec_driver_sql(
        "PRAGMA table_info(http_exchanges)")}
    if "review_status" in existing:
        return
    with op.batch_alter_table("http_exchanges") as batch:
        batch.add_column(sa.Column(
            "review_status", sa.String(length=20), nullable=False,
            server_default="pending"))


def downgrade():
    with op.batch_alter_table("http_exchanges") as batch:
        batch.drop_column("review_status")
