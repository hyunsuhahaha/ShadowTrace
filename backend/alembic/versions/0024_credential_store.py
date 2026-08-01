"""Add opt-in secret storage and provenance to credentials."""
from alembic import op
import sqlalchemy as sa


revision = "0024_credential_store"
down_revision = "0023_runbook_branch_engine"
branch_labels = None
depends_on = None


def upgrade():
    # Idempotent: a database first built by SQLAlchemy create_all (adopted into
    # Alembic) already carries these columns, so only add the missing ones.
    bind = op.get_bind()
    existing = {row[1] for row in bind.exec_driver_sql(
        "PRAGMA table_info(credentials)")}
    additions = [
        ("secret", sa.Column("secret", sa.Text(), nullable=False,
                             server_default="")),
        ("source_kind", sa.Column("source_kind", sa.String(length=40),
                                  nullable=False, server_default="manual")),
        ("source_detail", sa.Column("source_detail", sa.Text(), nullable=False,
                                    server_default="")),
    ]
    missing = [(name, column) for name, column in additions if name not in existing]
    if not missing:
        return
    with op.batch_alter_table("credentials") as batch:
        for _name, column in missing:
            batch.add_column(column)


def downgrade():
    with op.batch_alter_table("credentials") as batch:
        batch.drop_column("source_detail")
        batch.drop_column("source_kind")
        batch.drop_column("secret")
