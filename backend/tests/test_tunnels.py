import asyncio
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Project, Target
from app.modules.tunnels import router
from app.modules.tunnels.router import render
from app.schemas import TunnelIn


def test_user_confirmed_local_tunnel_renders_argv_without_shell():
    body = TunnelIn(
        project_id=1, target_id=2, name="manual pivot", kind="local",
        ssh_host="10.10.10.10", username="student", bind_host="127.0.0.1",
        local_port=8080, remote_host="10.10.20.5", remote_port=80,
        confirmed=True)
    argv = render(body)
    assert argv[0] == "ssh"
    assert argv[-1] == "student@10.10.10.10"
    assert "127.0.0.1:8080:10.10.20.5:80" in argv


def test_tunnel_requires_explicit_scope_confirmation():
    body = TunnelIn(
        project_id=1, target_id=2, name="manual pivot", kind="dynamic",
        ssh_host="10.10.10.10", username="student", local_port=1080,
        confirmed=False)
    try:
        render(body)
    except ValueError:
        return
    raise AssertionError("unconfirmed tunnel was accepted")


def test_create_tunnel_endpoint_schedules_and_runs_the_background_task(tmp_path, monkeypatch):
    # Regression test for a bug where `create_tunnel` was a sync route: FastAPI
    # runs sync routes in a worker thread with no running event loop, so
    # `TunnelManager.start`'s `asyncio.create_task()` raised RuntimeError on
    # every call and the tunnel row was left orphaned in "ready" status with
    # no ssh process ever spawned. Exercising the real async endpoint (not
    # just the pure `render()` helper) is what would have caught it.
    engine = create_engine(f"sqlite:///{tmp_path / 'tunnels.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(router, "SessionLocal", factory)
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    # Swap the real `ssh ...` argv for a trivial subprocess so the test does
    # not attempt a real network connection while still exercising the
    # subprocess-spawn and status-update path in `TunnelManager._run`.
    monkeypatch.setattr(router, "render", lambda body: [sys.executable, "-c", "pass"])

    with factory() as db:
        project = Project(name="Tunnel Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
        db.add(target); db.flush()
        db.commit()
        body = TunnelIn(
            project_id=project.id, target_id=target.id, name="regression",
            kind="dynamic", ssh_host="10.10.10.10", username="student",
            local_port=1080, confirmed=True)

        async def run():
            created = await router.create_tunnel(body, db)
            await asyncio.sleep(0.3)
            return created

        row = asyncio.run(run())
        tunnel_id = row.id

    with factory() as db:
        finished = db.get(router.Tunnel, tunnel_id)
        assert finished.status == "completed"
        assert finished.pid is None
