"""Add hashcat attack-mode fields (combination/mask) to hash_crack_jobs."""
from alembic import op
import sqlalchemy as sa


revision = "0030_hash_crack_attack_mode"
down_revision = "0029_hash_crack_jobs"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    existing = {row[1] for row in bind.exec_driver_sql(
        "PRAGMA table_info(hash_crack_jobs)")}
    additions = [
        ("attack_mode", sa.Column("attack_mode", sa.String(length=1),
                                  nullable=False, server_default="0")),
        ("wordlist2_id", sa.Column("wordlist2_id", sa.String(length=80),
                                   nullable=False, server_default="")),
        ("mask", sa.Column("mask", sa.String(length=64), nullable=False,
                           server_default="")),
    ]
    missing = [(name, column) for name, column in additions if name not in existing]
    if not missing:
        return
    with op.batch_alter_table("hash_crack_jobs") as batch:
        for _name, column in missing:
            batch.add_column(column)


def downgrade():
    with op.batch_alter_table("hash_crack_jobs") as batch:
        batch.drop_column("mask")
        batch.drop_column("wordlist2_id")
        batch.drop_column("attack_mode")
