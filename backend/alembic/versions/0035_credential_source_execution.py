"""Add structured source_execution_kind/id pointers to credentials."""
from alembic import op
import sqlalchemy as sa


revision = "0035_credential_source_execution"
down_revision = "0034_graph_events"
branch_labels = None
depends_on = None


def upgrade():
    # Idempotent: a database first built by SQLAlchemy create_all (adopted into
    # Alembic) already carries these columns, so only add the missing ones.
    existing = {row[1] for row in op.get_bind().exec_driver_sql(
        "PRAGMA table_info(credentials)")}
    additions = [
        ("source_execution_kind", sa.Column(
            "source_execution_kind", sa.String(length=40), nullable=True)),
        ("source_execution_id", sa.Column(
            "source_execution_id", sa.Integer(), nullable=True)),
    ]
    missing = [(name, column) for name, column in additions if name not in existing]
    if not missing:
        return
    with op.batch_alter_table("credentials") as batch:
        for _name, column in missing:
            batch.add_column(column)


def downgrade():
    with op.batch_alter_table("credentials") as batch:
        batch.drop_column("source_execution_id")
        batch.drop_column("source_execution_kind")
