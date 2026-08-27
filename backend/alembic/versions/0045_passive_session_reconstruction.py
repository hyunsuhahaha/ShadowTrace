"""Add passive process, terminal, command, and remote-session candidates."""
from alembic import op
import sqlalchemy as sa


revision = "0045_session_reconstruction"
down_revision = "0044_raw_activity_events"
branch_labels = None
depends_on = None


def upgrade():
    existing = set(op.get_bind().exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).scalars().all())
    if "terminal_sessions" not in existing:
        op.create_table(
            "terminal_sessions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("session_key", sa.String(240), nullable=False, unique=True),
            sa.Column("boot_id", sa.String(64), nullable=False),
            sa.Column("sid", sa.Integer(), nullable=True),
            sa.Column("tty_nr", sa.Integer(), nullable=True),
            sa.Column("tty", sa.String(200), nullable=False),
            sa.Column("pid_namespace", sa.String(120), nullable=False),
            sa.Column("kind", sa.String(30), nullable=False),
            sa.Column("topology", sa.Text(), nullable=False),
            sa.Column("observer_ids", sa.Text(), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("confidence", sa.Integer(), nullable=False),
            sa.Column("loss_state", sa.String(120), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_terminal_sessions_boot_id", "terminal_sessions", ["boot_id"])
    if "process_instances" not in existing:
        op.create_table(
            "process_instances",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("process_key", sa.String(200), nullable=False, unique=True),
            sa.Column("terminal_session_id", sa.Integer(),
                      sa.ForeignKey("terminal_sessions.id"), nullable=True),
            sa.Column("boot_id", sa.String(64), nullable=False),
            sa.Column("pid", sa.Integer(), nullable=False),
            sa.Column("tgid", sa.Integer(), nullable=False),
            sa.Column("start_ticks", sa.String(40), nullable=False),
            sa.Column("ppid", sa.Integer(), nullable=True),
            sa.Column("sid", sa.Integer(), nullable=True),
            sa.Column("pgid", sa.Integer(), nullable=True),
            sa.Column("tty_nr", sa.Integer(), nullable=True),
            sa.Column("tpgid", sa.Integer(), nullable=True),
            sa.Column("tty", sa.String(200), nullable=False),
            sa.Column("pid_namespace", sa.String(120), nullable=False),
            sa.Column("mount_namespace", sa.String(120), nullable=False),
            sa.Column("network_namespace", sa.String(120), nullable=False),
            sa.Column("user_namespace", sa.String(120), nullable=False),
            sa.Column("cgroup", sa.Text(), nullable=False),
            sa.Column("executable", sa.Text(), nullable=False),
            sa.Column("argv", sa.Text(), nullable=False),
            sa.Column("cwd", sa.Text(), nullable=False),
            sa.Column("fd_topology", sa.Text(), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("exit_code", sa.Integer(), nullable=True),
            sa.Column("confidence", sa.Integer(), nullable=False),
            sa.Column("loss_state", sa.String(120), nullable=False),
            sa.Column("evidence_event_ids", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_process_instances_terminal_session_id", "process_instances",
                        ["terminal_session_id"])
        op.create_index("ix_process_instances_boot_id", "process_instances", ["boot_id"])
        op.create_index("ix_process_instances_pid", "process_instances", ["pid"])
    if "command_activities" not in existing:
        op.create_table(
            "command_activities",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("activity_key", sa.String(240), nullable=False, unique=True),
            sa.Column("terminal_session_id", sa.Integer(),
                      sa.ForeignKey("terminal_sessions.id"), nullable=False),
            sa.Column("primary_process_id", sa.Integer(),
                      sa.ForeignKey("process_instances.id"), nullable=True),
            sa.Column("kind", sa.String(30), nullable=False),
            sa.Column("command", sa.Text(), nullable=False),
            sa.Column("cwd", sa.Text(), nullable=False),
            sa.Column("pgid", sa.Integer(), nullable=True),
            sa.Column("is_pipeline", sa.Boolean(), nullable=False),
            sa.Column("is_background", sa.Boolean(), nullable=False),
            sa.Column("stdin_target", sa.Text(), nullable=False),
            sa.Column("stdout_target", sa.Text(), nullable=False),
            sa.Column("stderr_target", sa.Text(), nullable=False),
            sa.Column("process_instance_ids", sa.Text(), nullable=False),
            sa.Column("evidence_event_ids", sa.Text(), nullable=False),
            sa.Column("evidence_streams", sa.Text(), nullable=False),
            sa.Column("inference", sa.Text(), nullable=False),
            sa.Column("sensitive", sa.Boolean(), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("confidence", sa.Integer(), nullable=False),
            sa.Column("loss_state", sa.String(120), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_command_activities_terminal_session_id", "command_activities",
                        ["terminal_session_id"])
    if "remote_session_candidates" not in existing:
        op.create_table(
            "remote_session_candidates",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("candidate_key", sa.String(240), nullable=False, unique=True),
            sa.Column("terminal_session_id", sa.Integer(),
                      sa.ForeignKey("terminal_sessions.id"), nullable=False),
            sa.Column("process_instance_id", sa.Integer(),
                      sa.ForeignKey("process_instances.id"), nullable=False),
            sa.Column("client_activity_id", sa.Integer(),
                      sa.ForeignKey("command_activities.id"), nullable=True),
            sa.Column("destination", sa.String(300), nullable=False),
            sa.Column("username", sa.String(160), nullable=False),
            sa.Column("evidence_event_ids", sa.Text(), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("confidence", sa.Integer(), nullable=False),
            sa.Column("loss_state", sa.String(120), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade():
    existing = set(op.get_bind().exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).scalars().all())
    for table in ("remote_session_candidates", "command_activities",
                  "process_instances", "terminal_sessions"):
        if table in existing:
            op.drop_table(table)
