from __future__ import annotations
import hashlib
import io
import json
import secrets
import zipfile
from pathlib import Path
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...database import get_db
from ...models import (Evidence, ExploitResearch, Finding, FindingEvidence, GraphNode, Project,
                       Service, Target)
from ...schemas import ArchiveExtractIn, EvidenceOut, EvidenceUpdate
from ...time import utcnow
from ..core.support import safe_part
from ..graph import service as graph_service
from ..hash_cracking.router import run_zip2john
from ..scan_center.service import _safe

router = APIRouter(prefix="/api/evidence", tags=["Evidence"])
MAX_FILE = 50 * 1024 * 1024
MAX_PREVIEW = 256 * 1024
KINDS = {"screenshot", "command_output", "http", "nmap", "flag",
         "attachment", "markdown"}
TEXT_EXTENSIONS = {
    ".txt", ".log", ".xml", ".json", ".md", ".csv", ".yaml", ".yml",
    # Web app/config source pulled off a target (LFI, exposed .git, anon
    # FTP/SMB share, ...) is plain text too -- reading it for hardcoded DB
    # creds or a password hash is standard whitebox review, not something
    # this list was ever trying to exclude, it just never grew past the
    # command-output-shaped extensions above.
    ".php", ".phtml", ".asp", ".aspx", ".jsp", ".py", ".rb", ".js", ".ts",
    ".java", ".go", ".pl", ".c", ".cpp", ".h", ".sh", ".sql",
    ".html", ".htm", ".conf", ".cnf", ".ini", ".env", ".ps1",
}


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


@router.get("", response_model=list[EvidenceOut])
def evidence(target_id: int | None = None, project_id: int | None = None,
             db: Session = Depends(get_db)):
    statement = select(Evidence).order_by(Evidence.id.desc())
    if target_id:
        statement = statement.where(Evidence.target_id == target_id)
    if project_id:
        statement = statement.where(Evidence.project_id == project_id)
    return db.scalars(statement.limit(1000)).all()


def validate_links(db: Session, project_id: int, target_id: int,
                   service_id: int | None):
    target = need(db, Target, target_id)
    if target.project_id != project_id:
        raise HTTPException(400, "Target does not belong to the project")
    if service_id:
        service = need(db, Service, service_id)
        if service.target_id != target.id:
            raise HTTPException(400, "Service does not belong to the target")
    return need(db, Project, project_id), target


@router.post("/upload", response_model=EvidenceOut, status_code=201)
async def upload_evidence(
    project_id: int = Form(...), target_id: int = Form(...),
    title: str = Form(...), kind: str = Form("attachment"),
    description: str = Form(""), service_id: int | None = Form(None),
    source_type: str = Form("upload"), source_id: int | None = Form(None),
    exploit_research_id: int | None = Form(None),
    sensitivity: str = Form("normal"), include_report: bool = Form(False),
    file: UploadFile = File(...), db: Session = Depends(get_db),
):
    # Keep direct Python callers (including maintenance scripts and tests)
    # compatible with FastAPI's Form default object.
    if not isinstance(exploit_research_id, int):
        exploit_research_id = None
    project, target = validate_links(db, project_id, target_id, service_id)
    if exploit_research_id:
        research = need(db, ExploitResearch, exploit_research_id)
        if (research.project_id != project_id or research.target_id != target_id
                or (service_id and research.service_id != service_id)):
            raise HTTPException(400, "Exploit Research belongs to another scope")
    if not title.strip():
        raise HTTPException(400, "Evidence title is required")
    if kind not in KINDS or sensitivity not in ("normal", "sensitive", "secret"):
        raise HTTPException(400, "Invalid evidence classification")
    content = await file.read(MAX_FILE + 1)
    if len(content) > MAX_FILE:
        raise HTTPException(413, "Evidence file exceeds 50 MiB")
    digest = hashlib.sha256(content).hexdigest()
    duplicate = db.scalar(select(Evidence).where(
        Evidence.project_id == project_id, Evidence.sha256 == digest))
    row = Evidence(project_id=project_id, target_id=target_id,
        service_id=service_id, title=title[:200], description=description[:20000],
        kind=kind, source_type=source_type[:40], source_id=source_id,
        exploit_research_id=exploit_research_id,
        original_name=Path(file.filename or "evidence.bin").name[:255],
        sha256=digest, size=len(content), sensitivity=sensitivity,
        include_report=include_report, duplicate_of=duplicate.id if duplicate else None)
    db.add(row); db.flush()
    folder = (WORKSPACE_DIR / "projects" / _safe(project.name) / "targets" /
              _safe(target.ip) / "evidence" / str(row.id))
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / _safe(row.original_name)
    path.write_bytes(content)
    row.file_path = str(path)
    db.commit(); db.refresh(row)
    return row


@router.post("/notes", response_model=EvidenceOut, status_code=201)
def create_note(project_id: int, target_id: int, body: EvidenceUpdate,
                db: Session = Depends(get_db)):
    validate_links(db, project_id, target_id, body.service_id)
    values = body.model_dump(exclude={"tags"})
    row = Evidence(project_id=project_id, target_id=target_id,
                   kind="markdown", source_type="note",
                   tags=json.dumps(body.tags, ensure_ascii=False), **values)
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.patch("/{ident}", response_model=EvidenceOut)
def update_evidence(ident: int, body: EvidenceUpdate,
                    db: Session = Depends(get_db)):
    row = need(db, Evidence, ident)
    validate_links(db, row.project_id, row.target_id, body.service_id)
    for key, value in body.model_dump(exclude={"tags"}).items():
        setattr(row, key, value)
    row.tags = json.dumps(body.tags, ensure_ascii=False)
    db.commit(); db.refresh(row)
    return row


@router.get("/{ident}/file")
def evidence_file(ident: int, db: Session = Depends(get_db)):
    row = need(db, Evidence, ident)
    path = Path(row.file_path)
    if not row.file_path or not path.is_file():
        raise HTTPException(410, "Evidence file is no longer available")
    return FileResponse(path, filename=row.original_name,
                        media_type="application/octet-stream")


@router.get("/{ident}/preview")
def evidence_preview(ident: int, db: Session = Depends(get_db)):
    row = need(db, Evidence, ident)
    if row.kind == "markdown" and row.markdown:
        return {"content": row.markdown, "truncated": False, "language": "markdown"}
    path = Path(row.file_path)
    if not row.file_path or not path.is_file():
        raise HTTPException(410, "Evidence file is no longer available")
    extension = Path(row.original_name).suffix.lower()
    if row.kind not in {"command_output", "http", "nmap", "flag"} \
            and extension not in TEXT_EXTENSIONS:
        raise HTTPException(415, "Evidence is not a previewable text file")
    content = path.read_bytes()[:MAX_PREVIEW + 1]
    if b"\x00" in content:
        raise HTTPException(415, "Evidence is not a previewable text file")
    truncated = len(content) > MAX_PREVIEW
    text = content[:MAX_PREVIEW].decode("utf-8", errors="replace")
    language = "xml" if extension == ".xml" else "json" if extension == ".json" else "text"
    return {"content": text, "truncated": truncated, "language": language}


@router.get("/{ident}/archive")
def evidence_archive(ident: int, db: Session = Depends(get_db)):
    """List a zip evidence's members so the operator can pick which ones are
    worth pulling back out onto the graph -- mirrors promote-download's own
    per-file picker (interactive_session_ftp_downloads), just one level
    deeper into an archive instead of a session's cwd."""
    row = need(db, Evidence, ident)
    path = Path(row.file_path)
    if not row.file_path or not path.is_file():
        raise HTTPException(410, "Evidence file is no longer available")
    if not zipfile.is_zipfile(path):
        raise HTTPException(415, "Evidence is not a zip archive")
    entries = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            # Listing a member's metadata never needs its password -- only
            # actually reading its bytes (extract_archive_entry) does. Flag
            # 0x1 marks that read as needing one, so the UI can say so up
            # front instead of the operator finding out via a failed click.
            entries.append({"name": info.filename, "size": info.file_size,
                            "encrypted": bool(info.flag_bits & 0x1)})
            if len(entries) >= 500:  # a huge listing is no longer a quick pick
                break
    return {"entries": entries}


@router.post("/{ident}/zip2john")
def evidence_zip2john(ident: int, db: Session = Depends(get_db)):
    """Runs zip2john against an evidence row's own archive on disk -- the
    zip already made the trip into this app once (download or extraction),
    so cracking its password is a straight handoff into Hash Cracking
    instead of asking the operator to download the same file again just to
    re-upload it there by hand."""
    row = need(db, Evidence, ident)
    path = Path(row.file_path)
    if not row.file_path or not path.is_file():
        raise HTTPException(410, "Evidence file is no longer available")
    if not zipfile.is_zipfile(path):
        raise HTTPException(415, "Evidence is not a zip archive")
    return run_zip2john(path.read_bytes())


@router.post("/{ident}/extract", status_code=201)
def extract_archive_entry(ident: int, body: ArchiveExtractIn, db: Session = Depends(get_db)):
    """Same idea as promote-download/promote-file: pull one archive member
    out as its own Evidence + Draft Finding, so a zip an operator downloaded
    stops being a dead end that only offers a raw download. Only ever reads
    bytes back out of the archive (archive.read, never .extract()) and
    writes them under a name this endpoint generates itself, so a crafted
    entry name ("../../etc/passwd") has nothing to escape into."""
    row = need(db, Evidence, ident)
    path = Path(row.file_path)
    if not row.file_path or not path.is_file():
        raise HTTPException(410, "Evidence file is no longer available")
    if not zipfile.is_zipfile(path):
        raise HTTPException(415, "Evidence is not a zip archive")
    with zipfile.ZipFile(path) as archive:
        try:
            info = archive.getinfo(body.entry)
        except KeyError:
            raise HTTPException(404, "That entry is not in this archive") from None
        if info.is_dir():
            raise HTTPException(422, "That entry is a folder, not a file")
        if info.file_size > MAX_FILE:
            raise HTTPException(413, "Archive entry is too large to extract")
        try:
            content = archive.read(
                info, pwd=body.password.encode() if body.password else None)
        except RuntimeError as exc:
            # zipfile raises a bare RuntimeError (no dedicated exception
            # type) for both "wrong/missing password" and "no password
            # given". A blank body.password means the operator hasn't tried
            # one yet -- point at Hash Cracking; a non-blank one means the
            # password they gave was wrong, not that none exists.
            if "password" not in str(exc).lower():
                raise
            if not body.password:
                raise HTTPException(
                    422, "이 항목은 암호로 보호되어 있습니다. Hash Cracking에서 "
                    "zip 원본을 zip2john으로 크랙한 뒤 암호를 입력하세요.") from None
            raise HTTPException(422, "입력한 암호가 올바르지 않습니다.") from None
    entry_name = Path(info.filename.replace("\\", "/")).name or info.filename
    output_path = path.parent / f"extracted-{secrets.token_hex(6)}-{safe_part(entry_name)}"
    output_path.write_bytes(content)
    evidence = Evidence(
        project_id=row.project_id, target_id=row.target_id, service_id=row.service_id,
        title=f"압축 해제: {entry_name}",
        description=f"{row.title}에서 압축 해제 · {info.filename}",
        kind="attachment", source_type="archive_extract", source_id=row.id,
        file_path=str(output_path), original_name=entry_name,
        sha256=hashlib.sha256(content).hexdigest(), size=len(content),
        hostname=row.hostname, include_report=False,
    )
    db.add(evidence); db.flush()
    finding = Finding(
        project_id=row.project_id, target_id=row.target_id, service_id=row.service_id,
        title=f"압축 해제: {entry_name}", status="Draft",
        reproduction_steps=f"{row.title}에서 압축 해제\n\n{info.filename}")
    db.add(finding); db.flush()
    db.add(FindingEvidence(finding_id=finding.id, evidence_id=evidence.id, is_primary=True))
    # docs/SPEC_GRAPH_TRACKER.md §6.1 "노드 연결 원칙" -- the archive's own
    # finding/technique node yielded this one, not the bare host/service
    # sync_from_project()'s default projection would otherwise fall back to
    # (Finding has no graph_parent_node_id column of its own, so this node
    # is created directly here, same pattern promote_download already uses).
    source_node = db.get(GraphNode, body.graph_node_id) if body.graph_node_id else None
    if (source_node and source_node.project_id == row.project_id
            and source_node.type in {"technique", "finding"}):
        meta = {"severity": finding.severity, "category": finding.category, "evidenceCount": 1}
        if body.password:
            # A one-shot "unlock" cue on the canvas (GraphCanvas.tsx) instead
            # of the crack/scan/shell activity language, none of which fit
            # "this was already sitting there encrypted, now it's open".
            meta["unlockedAt"] = utcnow().isoformat()
        finding_node = graph_service.create_node(
            db, row.project_id, "finding", label=finding.title,
            source_ref=json.dumps(
                {"module": "findings", "kind": "finding", "id": finding.id}, sort_keys=True),
            meta=json.dumps(meta))
        graph_service.create_edge(
            db, row.project_id, source_node.id, finding_node.id, "yielded")
    db.commit()
    return {"finding_id": finding.id, "evidence_id": evidence.id}


@router.post("/export")
def export_evidence(ids: list[int], db: Session = Depends(get_db)):
    if not ids or len(ids) > 500:
        raise HTTPException(400, "Select between 1 and 500 evidence records")
    rows = db.scalars(select(Evidence).where(Evidence.id.in_(ids))).all()
    output = io.BytesIO()
    manifest = []
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for row in rows:
            manifest.append({
                "id": row.id, "title": row.title, "kind": row.kind,
                "sha256": row.sha256, "source_type": row.source_type,
                "source_id": row.source_id, "sensitivity": row.sensitivity,
            })
            if row.file_path and (path := Path(row.file_path)).is_file():
                archive.write(path, f"{row.id}-{_safe(row.original_name)}")
            elif row.markdown:
                archive.writestr(f"{row.id}-note.md", row.markdown)
        archive.writestr("manifest.json",
                         json.dumps(manifest, ensure_ascii=False, indent=2))
    return Response(output.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition":
                             'attachment; filename="evidence-export.zip"'})
