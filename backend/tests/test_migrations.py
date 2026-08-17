import os
import subprocess
import sys
from pathlib import Path
from sqlalchemy import create_engine, inspect, text


BACKEND = Path(__file__).parents[1]


def environment(tmp_path, name):
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": ".",
        "OSCP_WORKSPACE_DB": str(tmp_path / f"{name}.db"),
        "OSCP_WORKSPACE_CONFIG": str(tmp_path / "config"),
        "OSCP_WORKSPACE_DATA": str(tmp_path / "data"),
        "OSCP_WORKSPACE_STATE": str(tmp_path / "state"),
        "OSCP_WORKSPACE_ROOT": str(tmp_path / "workspace"),
        "OSCP_ALLOW_ROOT": "1",
        "OSCP_BACKEND_BIND": "127.0.0.1",
    })
    return env


def run(*args, env):
    return subprocess.run(
        args, cwd=BACKEND, env=env, check=True, capture_output=True, text=True)


def test_migrate_repairs_tables_created_ahead_of_alembic(tmp_path):
    env = environment(tmp_path, "contaminated")
    run(sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade",
        "0013_exploit_local_runs", env=env)
    run(sys.executable, "-c",
        "from app.database import Base,engine; from app import models; "
        "Base.metadata.create_all(engine)", env=env)

    run(sys.executable, "-m", "app.migrations", env=env)

    engine = create_engine(f"sqlite:///{env['OSCP_WORKSPACE_DB']}")
    with engine.connect() as connection:
        assert connection.scalar(text(
            "select version_num from alembic_version")) == "0042_autorecon_runs"
    indexes = {item["name"] for item in inspect(engine).get_indexes(
        "runbook_template_versions")}
    assert "uq_runbook_template_version" in indexes


def test_importing_app_does_not_create_unmigrated_tables(tmp_path):
    env = environment(tmp_path, "clean")
    run(sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade",
        "0013_exploit_local_runs", env=env)

    run(sys.executable, "-c", "import app.main", env=env)

    engine = create_engine(f"sqlite:///{env['OSCP_WORKSPACE_DB']}")
    assert "runbook_templates" not in inspect(engine).get_table_names()


def test_migrate_repairs_hybrid_schema_from_repeated_create_all(tmp_path):
    env = environment(tmp_path, "hybrid")
    run(sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade",
        "0014_runbooks", env=env)
    # create_all adds later tables but cannot add later columns to existing tables.
    run(sys.executable, "-c",
        "from app.database import Base,engine; from app import models; "
        "Base.metadata.create_all(engine)", env=env)

    run(sys.executable, "-m", "app.migrations", env=env)

    engine = create_engine(f"sqlite:///{env['OSCP_WORKSPACE_DB']}")
    columns = {item["name"] for item in inspect(engine).get_columns(
        "runbook_step_instances")}
    assert {
        "condition", "timer_started_at", "elapsed_seconds", "node_key",
        "node_type", "transitions", "error_policy", "approval", "activation",
        "decision_trace", "approval_status", "attempts", "last_error",
    } <= columns
    indexes = {item["name"] for item in inspect(engine).get_indexes(
        "runbook_step_instances")}
    assert "ix_runbook_step_instances_activation" in indexes
    with engine.connect() as connection:
        assert connection.scalar(text(
            "select version_num from alembic_version")) == "0042_autorecon_runs"


def test_alembic_database_accepts_direct_report_finding(tmp_path):
    env = environment(tmp_path, "direct-finding")
    run(sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade",
        "head", env=env)
    run(sys.executable, "-c",
        "from app.database import SessionLocal; "
        "from app.models import Project,Finding; "
        "s=SessionLocal(); p=Project(name='Direct'); s.add(p); s.flush(); "
        "s.add(Finding(project_id=p.id,title='Direct report finding')); "
        "s.commit()", env=env)
    engine = create_engine(f"sqlite:///{env['OSCP_WORKSPACE_DB']}")
    columns = {item["name"]: item for item in inspect(engine).get_columns(
        "findings")}
    assert columns["observation_id"]["nullable"] is True
