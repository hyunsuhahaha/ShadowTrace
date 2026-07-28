from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return an aware UTC timestamp for persisted audit records."""
    return datetime.now(timezone.utc)
