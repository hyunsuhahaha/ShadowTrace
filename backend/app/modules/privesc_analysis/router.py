from __future__ import annotations
import hashlib
import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...database import get_db
from ...models import Evidence, Project, Target
from ...time import utcnow
from ..scan_center.service import _safe
from .gtfobins import match_gtfobins
from .schemas import LinpeasIn, SuidScanIn

router = APIRouter(tags=["Privesc Analysis"])

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
# linpeas.sh's own legend (printed near the top of every run): "RED/YELLOW:
# 95% a PE vector" is its highest-confidence marker; plain red/yellow are its
# ordinary "worth a look" highlight colors. Everything before the tool's own
# "Starting LinPEAS..." banner line is ASCII art, credits and a legend, not
# findings, and shares the same colors, so it is excluded rather than parsed.
CRITICAL_MARK = "\x1b[1;31;103m"
HIGH_MARK = "\x1b[1;31m"
MEDIUM_MARK = "\x1b[1;33m"
BOUNDARY = "starting linpeas"


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def parse_linpeas(raw: str) -> dict[str, list[str]]:
    lines = raw.splitlines()
    stripped = [ANSI_ESCAPE.sub("", line) for line in lines]
    start = 0
    for index, text in enumerate(stripped):
        if BOUNDARY in text.lower():
            start = index + 1
            break
    critical: list[str] = []
    high: list[str] = []
    medium: list[str] = []
    for raw_line, text in zip(lines[start:], stripped[start:]):
        cleaned = text.strip()
        if not cleaned:
            continue
        if CRITICAL_MARK in raw_line:
            critical.append(cleaned)
        elif HIGH_MARK in raw_line:
            high.append(cleaned)
        elif MEDIUM_MARK in raw_line:
            medium.append(cleaned)
    return {"critical": critical, "high": high, "medium": medium}


@router.post("/api/targets/{target_id}/linpeas")
def analyze_linpeas(target_id: int, body: LinpeasIn, db: Session = Depends(get_db)):
    target = need(db, Target, target_id)
    project = need(db, Project, target.project_id)
    result = parse_linpeas(body.output)

    target_dir = (WORKSPACE_DIR / "projects" / _safe(project.name) /
                  "targets" / _safe(target.ip) / "privesc-analysis")
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = target_dir / f"{utcnow():%Y%m%d%H%M%S}_linpeas.txt"
    output_path.write_text(body.output, encoding="utf-8")
    content = body.output.encode()
    evidence = Evidence(
        project_id=project.id, target_id=target.id,
        title=f"LinPEAS output · {target.hostname or target.ip}",
        description=(f"critical {len(result['critical'])} · high {len(result['high'])} · "
                     f"medium {len(result['medium'])} 개 항목 자동 분류"),
        kind="linpeas_output", source_type="linpeas_output",
        file_path=str(output_path), original_name=output_path.name,
        sha256=hashlib.sha256(content).hexdigest(), size=len(content),
        hostname=target.hostname or target.ip, sensitivity="sensitive",
        include_report=False,
    )
    db.add(evidence); db.commit(); db.refresh(evidence)
    return {**result, "evidence_id": evidence.id}


@router.post("/api/targets/{target_id}/suid-scan")
def analyze_suid(target_id: int, body: SuidScanIn, db: Session = Depends(get_db)):
    """Matches `find / -perm -4000 -type f`-style output against a curated
    set of GTFOBins SUID entries -- a static reference lookup, not a live
    exploit: it only tells the user which binaries are worth reading up on
    and where."""
    target = need(db, Target, target_id)
    project = need(db, Project, target.project_id)
    matches = match_gtfobins(body.output)

    target_dir = (WORKSPACE_DIR / "projects" / _safe(project.name) /
                  "targets" / _safe(target.ip) / "privesc-analysis")
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = target_dir / f"{utcnow():%Y%m%d%H%M%S}_suid-scan.txt"
    output_path.write_text(body.output, encoding="utf-8")
    content = body.output.encode()
    evidence = Evidence(
        project_id=project.id, target_id=target.id,
        title=f"SUID scan · {target.hostname or target.ip}",
        description=f"GTFOBins과 일치하는 SUID 바이너리 {len(matches)}개",
        kind="suid_scan", source_type="suid_scan",
        file_path=str(output_path), original_name=output_path.name,
        sha256=hashlib.sha256(content).hexdigest(), size=len(content),
        hostname=target.hostname or target.ip, sensitivity="sensitive",
        include_report=False,
    )
    db.add(evidence); db.commit(); db.refresh(evidence)
    return {"matches": matches, "evidence_id": evidence.id}
