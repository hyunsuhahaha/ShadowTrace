"""Add loss-aware generic passive endpoint events."""
from alembic import op
import sqlalchemy as sa


revision = "0044_raw_activity_events"
down_revision = "0043_passive_activities"
branch_labels = None
depends_on = None


def upgrade():
    existing = op.get_bind().exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).scalars().all()
    if "raw_activity_events" in existing:
        return
    op.create_table(
        "raw_activity_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_key", sa.String(200), nullable=False, unique=True),
        sa.Column("observer_id", sa.String(64), nullable=False),
        sa.Column("boot_id", sa.String(64), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("monotonic_ns", sa.BigInteger(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("tid", sa.Integer(), nullable=True),
        sa.Column("ppid", sa.Integer(), nullable=True),
        sa.Column("uid", sa.Integer(), nullable=True),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("capture_state", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("loss_before", sa.Integer(), nullable=False),
        sa.Column("sensitive", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_raw_activity_events_observer_id", "raw_activity_events", ["observer_id"])
    op.create_index("ix_raw_activity_events_kind", "raw_activity_events", ["kind"])
    op.create_index("ix_raw_activity_events_pid", "raw_activity_events", ["pid"])


def downgrade():
    existing = op.get_bind().exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).scalars().all()
    if "raw_activity_events" in existing:
        op.drop_table("raw_activity_events")
