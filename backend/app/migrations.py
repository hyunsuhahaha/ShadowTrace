"""Apply Alembic migrations while adopting pre-Alembic local databases."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text
from .database import Base, engine, ensure_compatible_schema
from . import models  # noqa: F401

RUNBOOK_STAGES = (
    ("0023_runbook_branch_engine",
     {"runbook_step_templates", "runbook_step_instances"},
     {"runbook_step_templates": {
          "node_key", "node_type", "transitions", "error_policy", "approval"},
      "runbook_step_instances": {
          "node_key", "node_type", "transitions", "error_policy", "approval",
          "activation", "decision_trace", "approval_status", "approval_reason",
          "approved_by", "attempts", "last_error"}}),
    ("0022_service_intelligence",
     {"runbook_step_templates", "runbook_step_instances", "services",
      "service_observations"},
     {"services": {"cpe", "tls", "detection_evidence"},
      "service_observations": {"cpe", "tls", "detection_evidence"},
      "runbook_step_templates": {"guidance"},
      "runbook_step_instances": {"guidance", "outcome", "assessment"}}),
    ("0017_builtin_runbooks",
     {"runbook_recommendation_dismissals"},
     {"runbook_templates": {"builtin_key"},
      "runbook_step_instances": {"timer_started_at", "elapsed_seconds"}}),
    ("0016_runbook_operations",
     {"runbook_recommendation_dismissals"},
     {"runbook_step_instances": {"timer_started_at", "elapsed_seconds"}}),
    ("0015_runbook_workflow",
     {"credentials", "runbook_step_credentials", "runbook_observations", "findings"},
     {"runbook_step_templates": {"condition"},
      "runbook_step_instances": {"condition"}}),
    ("0014_runbooks",
     {"runbook_templates", "runbook_template_versions", "runbook_step_templates",
      "runbook_instances", "runbook_step_instances", "runbook_step_evidence",
      "runbook_step_executions", "runbook_activity_events"},
     {}),
)
REVISION_ORDER = {
    "0013_exploit_local_runs": 13,
    "0014_runbooks": 14,
    "0015_runbook_workflow": 15,
    "0016_runbook_operations": 16,
    "0017_builtin_runbooks": 17,
    "0022_service_intelligence": 22,
    "0023_runbook_branch_engine": 23,
}
RUNBOOK_INDEXES = (
    ("uq_runbook_templates_builtin_key", "runbook_templates",
     "builtin_key", True),
    ("uq_runbook_template_version", "runbook_template_versions",
     "template_id, version", True),
    ("uq_runbook_step_position", "runbook_step_templates",
     "version_id, position", True),
    ("uq_runbook_instance_scope", "runbook_instances",
     "target_id, service_id, version_id", True),
    ("uq_runbook_instance_step_position", "runbook_step_instances",
     "instance_id, position", True),
    ("uq_runbook_recommendation_dismissal", "runbook_recommendation_dismissals",
     "service_id, version_id, fingerprint", True),
    ("ix_runbook_template_versions_template_id", "runbook_template_versions",
     "template_id", False),
    ("ix_runbook_step_templates_version_id", "runbook_step_templates",
     "version_id", False),
    ("ix_runbook_instances_project_id", "runbook_instances", "project_id", False),
    ("ix_runbook_instances_target_id", "runbook_instances", "target_id", False),
    ("ix_runbook_instances_service_id", "runbook_instances", "service_id", False),
    ("ix_runbook_step_instances_instance_id", "runbook_step_instances",
     "instance_id", False),
    ("ix_runbook_activity_events_instance_id", "runbook_activity_events",
     "instance_id", False),
    ("ix_credentials_project_id", "credentials", "project_id", False),
    ("ix_runbook_observations_step_id", "runbook_observations", "step_id", False),
    ("ix_findings_project_id", "findings", "project_id", False),
    ("ix_runbook_recommendation_dismissals_service",
     "runbook_recommendation_dismissals", "service_id", False),
    ("ix_runbook_step_instances_activation", "runbook_step_instances",
     "instance_id, activation", False),
)
RUNBOOK_COLUMN_DDL = {
    ("runbook_step_templates", "node_key"):
        "ALTER TABLE runbook_step_templates ADD COLUMN node_key VARCHAR(120) NOT NULL DEFAULT ''",
    ("runbook_step_templates", "node_type"):
        "ALTER TABLE runbook_step_templates ADD COLUMN node_type VARCHAR(32) NOT NULL DEFAULT 'manual_check'",
    ("runbook_step_templates", "transitions"):
        "ALTER TABLE runbook_step_templates ADD COLUMN transitions TEXT NOT NULL DEFAULT '[]'",
    ("runbook_step_templates", "error_policy"):
        "ALTER TABLE runbook_step_templates ADD COLUMN error_policy TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_templates", "approval"):
        "ALTER TABLE runbook_step_templates ADD COLUMN approval TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_instances", "node_key"):
        "ALTER TABLE runbook_step_instances ADD COLUMN node_key VARCHAR(120) NOT NULL DEFAULT ''",
    ("runbook_step_instances", "node_type"):
        "ALTER TABLE runbook_step_instances ADD COLUMN node_type VARCHAR(32) NOT NULL DEFAULT 'manual_check'",
    ("runbook_step_instances", "transitions"):
        "ALTER TABLE runbook_step_instances ADD COLUMN transitions TEXT NOT NULL DEFAULT '[]'",
    ("runbook_step_instances", "error_policy"):
        "ALTER TABLE runbook_step_instances ADD COLUMN error_policy TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_instances", "approval"):
        "ALTER TABLE runbook_step_instances ADD COLUMN approval TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_instances", "activation"):
        "ALTER TABLE runbook_step_instances ADD COLUMN activation VARCHAR(24) NOT NULL DEFAULT 'waiting'",
    ("runbook_step_instances", "decision_trace"):
        "ALTER TABLE runbook_step_instances ADD COLUMN decision_trace TEXT NOT NULL DEFAULT '[]'",
    ("runbook_step_instances", "approval_status"):
        "ALTER TABLE runbook_step_instances ADD COLUMN approval_status VARCHAR(24) NOT NULL DEFAULT 'not_required'",
    ("runbook_step_instances", "approval_reason"):
        "ALTER TABLE runbook_step_instances ADD COLUMN approval_reason TEXT NOT NULL DEFAULT ''",
    ("runbook_step_instances", "approved_by"):
        "ALTER TABLE runbook_step_instances ADD COLUMN approved_by VARCHAR(160) NOT NULL DEFAULT ''",
    ("runbook_step_instances", "attempts"):
        "ALTER TABLE runbook_step_instances ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
    ("runbook_step_instances", "last_error"):
        "ALTER TABLE runbook_step_instances ADD COLUMN last_error TEXT NOT NULL DEFAULT ''",
    ("services", "cpe"):
        "ALTER TABLE services ADD COLUMN cpe TEXT NOT NULL DEFAULT '[]'",
    ("services", "tls"):
        "ALTER TABLE services ADD COLUMN tls BOOLEAN NOT NULL DEFAULT 0",
    ("services", "detection_evidence"):
        "ALTER TABLE services ADD COLUMN detection_evidence TEXT NOT NULL DEFAULT '{}'",
    ("service_observations", "cpe"):
        "ALTER TABLE service_observations ADD COLUMN cpe TEXT NOT NULL DEFAULT '[]'",
    ("service_observations", "tls"):
        "ALTER TABLE service_observations ADD COLUMN tls BOOLEAN NOT NULL DEFAULT 0",
    ("service_observations", "detection_evidence"):
        "ALTER TABLE service_observations ADD COLUMN detection_evidence TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_templates", "guidance"):
        "ALTER TABLE runbook_step_templates ADD COLUMN guidance TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_instances", "guidance"):
        "ALTER TABLE runbook_step_instances ADD COLUMN guidance TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_instances", "outcome"):
        "ALTER TABLE runbook_step_instances ADD COLUMN outcome VARCHAR(24) NOT NULL DEFAULT 'unknown'",
    ("runbook_step_instances", "assessment"):
        "ALTER TABLE runbook_step_instances ADD COLUMN assessment TEXT NOT NULL DEFAULT '{}'",
    ("runbook_templates", "builtin_key"):
        "ALTER TABLE runbook_templates ADD COLUMN builtin_key VARCHAR(120)",
    ("runbook_step_templates", "condition"):
        "ALTER TABLE runbook_step_templates ADD COLUMN "
        "condition TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_instances", "condition"):
        "ALTER TABLE runbook_step_instances ADD COLUMN "
        "condition TEXT NOT NULL DEFAULT '{}'",
    ("runbook_step_instances", "timer_started_at"):
        "ALTER TABLE runbook_step_instances ADD COLUMN timer_started_at DATETIME",
    ("runbook_step_instances", "elapsed_seconds"):
        "ALTER TABLE runbook_step_instances ADD COLUMN "
        "elapsed_seconds INTEGER NOT NULL DEFAULT 0",
}


def adopt_metadata_created_runbooks(config: Config) -> str | None:
    """Repair databases where app import created ORM tables ahead of Alembic."""
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()
    current_order = REVISION_ORDER.get(current)
    if current_order is None:
        return None
    # Repeated create_all calls can produce later tables while leaving columns
    # from earlier ALTER migrations absent. Repair every known additive column
    # before deciding which complete stage the schema represents.
    with engine.begin() as connection:
        for (table, column), statement in RUNBOOK_COLUMN_DDL.items():
            if table in tables and column not in {
                    item["name"] for item in schema.get_columns(table)}:
                connection.execute(text(statement))
    schema = inspect(engine)
    stage = None
    for revision, required_tables, required_columns in RUNBOOK_STAGES:
        if not required_tables <= tables:
            continue
        with engine.begin() as connection:
            for table, columns in required_columns.items():
                existing = {
                    column["name"] for column in schema.get_columns(table)}
                for column in columns - existing:
                    statement = RUNBOOK_COLUMN_DDL.get((table, column))
                    if not statement:
                        return None
                    connection.execute(text(statement))
        schema = inspect(engine)
        if all(columns <= {
                column["name"] for column in schema.get_columns(table)}
               for table, columns in required_columns.items()):
            stage = revision
            break
    if not stage or REVISION_ORDER[stage] <= current_order:
        return None
    # create_all includes foreign keys but not migration-only indexes.
    with engine.begin() as connection:
        for name, table, columns, unique in RUNBOOK_INDEXES:
            if table in tables:
                connection.execute(text(
                    f"CREATE {'UNIQUE ' if unique else ''}INDEX IF NOT EXISTS "
                    f"{name} ON {table} ({columns})"))
    command.stamp(config, stage)
    return stage


def migrate() -> None:
    backend = Path(__file__).parents[1]
    config = Config(backend / "alembic.ini")
    config.set_main_option("script_location", str(backend / "alembic"))
    tables = set(inspect(engine).get_table_names())
    if not tables:
        command.upgrade(config, "head")
    elif "alembic_version" not in tables:
        Base.metadata.create_all(engine)
        ensure_compatible_schema()
        command.stamp(config, "head")
    else:
        adopt_metadata_created_runbooks(config)
        command.upgrade(config, "head")


if __name__ == "__main__":
    migrate()
