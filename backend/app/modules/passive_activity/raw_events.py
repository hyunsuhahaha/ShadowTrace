from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import STATE_DIR
from ...models import RawActivityEvent

EVENT_INBOX = STATE_DIR / "passive-event-inbox"
EVENT_ARCHIVE = STATE_DIR / "passive-event-archive"
KINDS = {"process_fork", "process_exec", "process_exit", "stdio_read",
         "stdio_write", "socket", "filesystem", "loss"}
CAPTURE_STATES = {"captured", "partial", "redacted", "lost"}
MAX_BATCH_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 1000
MAX_PAYLOAD_BYTES = 64 * 1024


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("event timestamp is missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def ingest_event_batch(db: Session, path: Path) -> dict[str, int]:
    path = path.resolve()
    if path.parent != EVENT_INBOX.resolve() or not path.is_file():
        raise ValueError("event batch is outside the passive event inbox")
    if path.stat().st_size > MAX_BATCH_BYTES:
        raise ValueError("event batch exceeds 10 MiB")
    batch = json.loads(path.read_text(encoding="utf-8"))
    if batch.get("schema") != 1:
        raise ValueError("unsupported passive event schema")
    observer_id = str(batch.get("observer_id", ""))
    boot_id = str(batch.get("boot_id", ""))
    events = batch.get("events")
    if not observer_id or len(observer_id) > 64 or not boot_id or len(boot_id) > 64:
        raise ValueError("invalid observer identity")
    if not isinstance(events, list) or not events or len(events) > MAX_EVENTS:
        raise ValueError("invalid passive event batch size")

    created = skipped = 0
    for raw in events:
        if not isinstance(raw, dict):
            raise ValueError("invalid passive event")
        sequence = int(raw["sequence"])
        event_key = f"{boot_id}:{observer_id}:{sequence}"
        if raw.get("event_key") != event_key:
            raise ValueError("passive event identity mismatch")
        if db.scalar(select(RawActivityEvent.id).where(
                RawActivityEvent.event_key == event_key)) is not None:
            skipped += 1
            continue
        kind = str(raw.get("kind", ""))
        state = str(raw.get("capture_state", "captured"))
        if kind not in KINDS or state not in CAPTURE_STATES:
            raise ValueError("invalid passive event kind or state")
        payload = raw.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("passive event payload must be an object")
        payload_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(payload_text.encode()) > MAX_PAYLOAD_BYTES:
            raise ValueError("passive event payload exceeds 64 KiB")
        confidence = int(raw.get("confidence", 100))
        loss_before = int(raw.get("loss_before", 0))
        if not 0 <= confidence <= 100 or loss_before < 0:
            raise ValueError("invalid passive event confidence or loss count")
        db.add(RawActivityEvent(
            event_key=event_key, observer_id=observer_id, boot_id=boot_id,
            sequence=sequence, kind=kind, source=str(raw.get("source", "ebpf"))[:40],
            monotonic_ns=int(raw.get("monotonic_ns", 0)),
            recorded_at=_timestamp(raw.get("recorded_at")),
            pid=int(raw["pid"]) if raw.get("pid") is not None else None,
            tid=int(raw["tid"]) if raw.get("tid") is not None else None,
            ppid=int(raw["ppid"]) if raw.get("ppid") is not None else None,
            uid=int(raw["uid"]) if raw.get("uid") is not None else None,
            payload=payload_text, capture_state=state, confidence=confidence,
            loss_before=loss_before, sensitive=bool(raw.get("sensitive", False)),
        ))
        created += 1
    db.commit()
    return {"created": created, "skipped": skipped}


def sync_event_inbox(db: Session) -> dict[str, int]:
    EVENT_INBOX.mkdir(parents=True, exist_ok=True)
    EVENT_ARCHIVE.mkdir(parents=True, exist_ok=True)
    os.chmod(EVENT_INBOX, 0o700)
    os.chmod(EVENT_ARCHIVE, 0o700)
    result = {"batches": 0, "events": 0, "skipped": 0, "failed": 0}
    for path in sorted(EVENT_INBOX.glob("*.json")):
        try:
            imported = ingest_event_batch(db, path)
            path.replace(EVENT_ARCHIVE / path.name)
            result["batches"] += 1
            result["events"] += imported["created"]
            result["skipped"] += imported["skipped"]
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            db.rollback()
            result["failed"] += 1
    return result
