import json

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import RawActivityEvent
from app.modules.passive_activity import raw_events


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
