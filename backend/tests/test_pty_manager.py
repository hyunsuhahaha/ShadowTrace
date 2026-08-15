import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.pty_manager as pty_manager_module
from app.database import Base
from app.models import InteractiveSession, Project, Target
from app.pty_manager import PtyManager


def _make_session_factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _make_row(factory, command):
    with factory() as db:
        project = Project(name="Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="box", ip="10.10.10.61")
        db.add(target); db.flush()
        row = InteractiveSession(target_id=target.id, template_id="manual-shell",
                                 command=command, cwd="/tmp", status="ready")
        db.add(row); db.commit()
        return row.id


class FakeWebSocket:
    """Minimal stand-in for FastAPI's WebSocket, matching the subset of the
    interface pty_manager.connect() actually uses: accept/receive (raw ASGI
    message dicts)/send_bytes/close. receive() raises like Starlette does
    once the peer is gone, which is what drives input_data()'s loop to end."""

    def __init__(self, messages=(), disconnected=False):
        self._messages = list(messages)
        self._disconnected = disconnected
        self.sent: list[bytes] = []
        self.closed_code: int | None = None

    async def accept(self):
        pass

    async def receive(self):
        if self._messages:
            return self._messages.pop(0)
        if self._disconnected:
            raise RuntimeError(
                'Cannot call "receive" once a disconnect message has been received.')
        # Block "forever" (until the test moves on / the task is cancelled),
        # the same way a real open socket with nothing more to say would.
        await asyncio.Event().wait()

    async def send_bytes(self, data):
        self.sent.append(data)

    async def close(self, code=1000):
        self.closed_code = code


def test_reconnect_within_grace_window_reuses_the_live_process(tmp_path):
    factory = _make_session_factory(tmp_path)
    session_id = _make_row(factory, "sleep 30")

    async def scenario():
        manager = PtyManager()
        manager.RECONNECT_GRACE_SECONDS = 5
        ws1 = FakeWebSocket(disconnected=True)
        await manager.connect(session_id, ["sleep", "30"], tmp_path,
                              tmp_path / "session.log", ws1)
        first_pid = manager.processes[session_id].pid
        assert first_pid is not None
        first_grace_handle = manager._grace_handles[session_id]
        finalize_task = manager._finalize_tasks[session_id]

        # Also disconnects immediately, so a fresh grace timer gets scheduled
        # again -- what matters here is that reattaching (a) cancelled the
        # *previous* timer instead of leaving it to fire on the now-stale
        # closure, and (b) reused the process instead of spawning a new one.
        ws2 = FakeWebSocket(disconnected=True)
        await manager.connect(session_id, ["sleep", "30"], tmp_path,
                              tmp_path / "session.log", ws2)
        assert manager.processes[session_id].pid == first_pid
        assert first_grace_handle.cancelled()

        await manager.stop(session_id)
        await finalize_task

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(pty_manager_module, "SessionLocal", factory)
    try:
        asyncio.run(scenario())
    finally:
        monkeypatch.undo()

    with factory() as db:
        row = db.get(InteractiveSession, session_id)
        assert row.status == "stopped"


def test_disconnect_with_no_reconnect_kills_the_process_after_grace(tmp_path):
    factory = _make_session_factory(tmp_path)
    session_id = _make_row(factory, "sleep 30")

    async def scenario():
        manager = PtyManager()
        manager.RECONNECT_GRACE_SECONDS = 0.05
        ws1 = FakeWebSocket(disconnected=True)
        await manager.connect(session_id, ["sleep", "30"], tmp_path,
                              tmp_path / "session.log", ws1)
        process = manager.processes[session_id]
        assert process.returncode is None

        await asyncio.sleep(0.3)
        assert process.returncode is not None
        assert session_id not in manager.processes

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(pty_manager_module, "SessionLocal", factory)
    try:
        asyncio.run(scenario())
    finally:
        monkeypatch.undo()

    with factory() as db:
        row = db.get(InteractiveSession, session_id)
        assert row.status == "stopped"
