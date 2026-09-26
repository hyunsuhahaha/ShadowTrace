import json
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import RawActivityEvent
from app.modules.passive_activity import raw_events
from app.modules.passive_activity import router


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_sync_event_batch_is_loss_aware_and_idempotent(tmp_path, monkeypatch):
    inbox, archive = tmp_path / "inbox", tmp_path / "archive"
    inbox.mkdir()
    monkeypatch.setattr(raw_events, "EVENT_INBOX", inbox)
    monkeypatch.setattr(raw_events, "EVENT_ARCHIVE", archive)
    event = {
        "event_key": "boot-1:observer-1:1",
        "sequence": 1,
        "kind": "stdio_read",
        "source": "ebpf",
        "monotonic_ns": 123,
        "recorded_at": "2026-08-27T12:00:00+00:00",
        "pid": 42,
        "tid": 42,
        "ppid": 10,
        "uid": 1000,
        "payload": {"fd": 0, "redacted_bytes": 8},
        "capture_state": "redacted",
        "confidence": 100,
        "loss_before": 3,
        "sensitive": True,
    }
    batch = {"schema": 1, "observer_id": "observer-1", "boot_id": "boot-1",
             "events": [event]}
    (inbox / "batch.json").write_text(json.dumps(batch))
    db = database()

    assert raw_events.sync_event_inbox(db) == {
        "batches": 1, "events": 1, "skipped": 0, "failed": 0}
    stored = db.query(RawActivityEvent).one()
    assert stored.kind == "stdio_read"
    assert stored.capture_state == "redacted"
    assert stored.loss_before == 3
    assert json.loads(stored.payload) == {"fd": 0, "redacted_bytes": 8}

    (inbox / "batch.json").write_text(json.dumps(batch))
    assert raw_events.sync_event_inbox(db) == {
        "batches": 1, "events": 0, "skipped": 1, "failed": 0}
    assert db.query(RawActivityEvent).count() == 1


def test_invalid_event_batch_stays_in_inbox(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(raw_events, "EVENT_INBOX", inbox)
    monkeypatch.setattr(raw_events, "EVENT_ARCHIVE", tmp_path / "archive")
    path = inbox / "bad.json"
    path.write_text(json.dumps({"schema": 99, "events": []}))
    db = database()

    assert raw_events.sync_event_inbox(db)["failed"] == 1
    assert path.exists()
    assert db.query(RawActivityEvent).count() == 0


def test_sync_keeps_legacy_shape_and_runs_reconstruction(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(raw_events, "EVENT_INBOX", inbox)
    monkeypatch.setattr(raw_events, "EVENT_ARCHIVE", tmp_path / "archive")
    monkeypatch.setattr(router, "sync_inbox", lambda _db: {"processed": 0, "failed": 0})
    event = {
        "event_key": "boot:observer:1", "sequence": 1, "kind": "process_exec",
        "source": "ebpf", "monotonic_ns": 1,
        "recorded_at": "2026-08-27T12:00:00+00:00", "pid": 42, "tid": 42,
        "ppid": 1, "uid": 1000, "capture_state": "captured", "confidence": 100,
        "loss_before": 0, "sensitive": False, "payload": {
            "start_ticks": "10", "sid": 42, "pgid": 42, "tpgid": 42,
            "tty_nr": 1, "argv": ["/usr/bin/id"], "executable": "/usr/bin/id",
            "fd_targets": {"0": "/dev/pts/1", "1": "/dev/pts/1", "2": "/dev/pts/1"},
        },
    }
    (inbox / "batch.json").write_text(json.dumps({
        "schema": 1, "observer_id": "observer", "boot_id": "boot", "events": [event]}))
    db = database()

    result = router.sync(db)

    assert result["processed"] == 0
    assert result["failed"] == 0
    assert result["raw_events"]["events"] == 1
    assert result["reconstruction"] == {
        "processes": 1, "sessions": 1, "commands": 1, "remote_candidates": 0}


def test_sync_serializes_overlapping_requests(monkeypatch):
    first_entered = Event()
    release_first = Event()
    second_started = Event()
    entries = []

    def sync_inbox(_db):
        entries.append(1)
        if len(entries) == 1:
            first_entered.set()
            assert release_first.wait(5)
        return {"processed": 0, "failed": 0}

    monkeypatch.setattr(router, "sync_inbox", sync_inbox)
    monkeypatch.setattr(router, "sync_event_inbox", lambda _db: {"events": 0})
    monkeypatch.setattr(router, "reconstruct", lambda _db, **_kwargs: {"processes": 0})
    class EmptyDatabase:
        def scalar(self, _query):
            return None

    db = EmptyDatabase()

    def second_request():
        second_started.set()
        return router.sync(db)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(router.sync, db)
        assert first_entered.wait(5)
        second = pool.submit(second_request)
        try:
            assert second_started.wait(5)
            time.sleep(0.05)
            assert len(entries) == 1
        finally:
            release_first.set()
        assert first.result(timeout=5)["processed"] == 0
        assert second.result(timeout=5)["processed"] == 0
    assert len(entries) == 2


def test_idle_sync_does_not_rebuild_existing_corpus(monkeypatch):
    db = database()
    calls = []
    monkeypatch.setattr(router, "sync_inbox", lambda _db: {"processed": 0, "failed": 0})
    monkeypatch.setattr(router, "sync_event_inbox", lambda _db: {
        "batches": 0, "events": 0, "skipped": 0, "failed": 0})
    monkeypatch.setattr(router, "reconstruct", lambda _db, **kwargs: (
        calls.append(kwargs["changed_event_ids"]) or {"processes": 0}))

    assert router.sync(db)["reconstruction"] == {"processes": 0}
    assert calls == [[]]
