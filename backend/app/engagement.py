"""Project RoE check shared by active assessment entry points."""
from __future__ import annotations

import ipaddress
import json
from datetime import timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .models import AssessmentAsset, ProjectRoe, Target
from .time import utcnow

ACTIONS = frozenset({"scan", "command", "web", "session", "post", "runbook"})


def _match_target(selector: str, target: Target) -> bool:
    value = selector.strip().lower()
    if not value:
        return False
    try:
        return ipaddress.ip_address(target.ip) in ipaddress.ip_network(value, strict=False)
    except ValueError:
        return value == (target.hostname or "").lower()


def _current(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def require_roe(db: Session, project_id: int, action: str,
                *, target: Target | None = None,
                asset: AssessmentAsset | None = None) -> None:
    if action not in ACTIONS:
        raise ValueError(f"Unknown RoE action: {action}")
    row = db.get(ProjectRoe, project_id)
    # Directly-created legacy rows in unit tests may have no RoE. All projects
    # created through the API and all migrated projects receive a draft row.
    if row is None:
        return
    now = utcnow()
    if row.status != "approved" or not row.valid_from or not row.valid_until:
        raise HTTPException(409, "Project Rules of Engagement are not approved")
    if not (_current(row.valid_from) <= now <= _current(row.valid_until)):
        raise HTTPException(409, "Project Rules of Engagement are outside the approved window")
    if action not in json.loads(row.allowed_actions or "[]"):
        raise HTTPException(409, f"Action '{action}' is not approved")
    if target is not None:
        if target.project_id != project_id:
            raise HTTPException(400, "Target belongs to another project")
        excluded = json.loads(row.excluded_targets or "[]")
        included = json.loads(row.included_targets or "[]")
        if any(_match_target(item, target) for item in excluded):
            raise HTTPException(409, "Target is excluded by the Rules of Engagement")
        if not any(_match_target(item, target) for item in included):
            raise HTTPException(409, "Target is outside the approved scope")
    if asset is not None:
        if asset.project_id != project_id:
            raise HTTPException(400, "Asset belongs to another project")
        if asset.scope_status != "in_scope" or asset.id not in json.loads(row.asset_ids or "[]"):
            raise HTTPException(409, "Asset is outside the approved scope")
