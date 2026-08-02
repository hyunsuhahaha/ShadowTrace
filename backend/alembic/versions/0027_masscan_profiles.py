"""Add masscan discovery profiles: engine/chain_kind on scan_profiles, parent link on scan_jobs."""
from alembic import op
import sqlalchemy as sa


revision = "0027_masscan_profiles"
down_revision = "0026_exchange_review_status"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()

    profile_columns = {row[1] for row in bind.exec_driver_sql(
        "PRAGMA table_info(scan_profiles)")}
    profile_additions = [
        ("engine", sa.Column("engine", sa.String(length=20), nullable=False,
                             server_default="nmap")),
        ("chain_kind", sa.Column("chain_kind", sa.String(length=40),
                                 nullable=False, server_default="")),
    ]
    missing_profile = [(name, column) for name, column in profile_additions
                       if name not in profile_columns]
    if missing_profile:
        with op.batch_alter_table("scan_profiles") as batch:
            for _name, column in missing_profile:
                batch.add_column(column)

    job_columns = {row[1] for row in bind.exec_driver_sql(
        "PRAGMA table_info(scan_jobs)")}
    if "parent_scan_id" not in job_columns:
        with op.batch_alter_table("scan_jobs") as batch:
            batch.add_column(sa.Column(
                "parent_scan_id", sa.Integer(), nullable=True))


def downgrade():
    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_column("parent_scan_id")
    with op.batch_alter_table("scan_profiles") as batch:
        batch.drop_column("chain_kind")
        batch.drop_column("engine")
