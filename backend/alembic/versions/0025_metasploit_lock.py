"""Track the single exam target a project has committed Metasploit/Meterpreter use to."""
from alembic import op
import sqlalchemy as sa


revision = "0025_metasploit_lock"
down_revision = "0024_credential_store"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    existing = {row[1] for row in bind.exec_driver_sql(
        "PRAGMA table_info(projects)")}
    # Plain column, no FK constraint: SQLite batch mode requires named
    # constraints to add one via ALTER, and this app never turns on
    # PRAGMA foreign_keys anyway (see database.py) — the relationship is
    # enforced at the application layer (main.py validates target_id).
    additions = [
        ("metasploit_target_id", sa.Column(
            "metasploit_target_id", sa.Integer(), nullable=True)),
        ("metasploit_locked_at", sa.Column(
            "metasploit_locked_at", sa.DateTime(timezone=True), nullable=True)),
    ]
    missing = [(name, column) for name, column in additions if name not in existing]
    if not missing:
        return
    with op.batch_alter_table("projects") as batch:
        for _name, column in missing:
            batch.add_column(column)


def downgrade():
    with op.batch_alter_table("projects") as batch:
        batch.drop_column("metasploit_locked_at")
        batch.drop_column("metasploit_target_id")
