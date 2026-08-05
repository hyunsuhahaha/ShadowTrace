from __future__ import annotations
import asyncio
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...database import get_db
from ...models import Credential, HashCrackJob, Project, Target
from ...time import utcnow
from ..scan_center.service import _safe
from . import catalog
from .manager import manager, parse_cracked
from .schemas import JobIn, JobOut, PromoteIn

router = APIRouter(prefix="/api/hash-cracking", tags=["Hash Cracking"])
# A hashcat mask is passed as a bare argv token (?u?l?l?l?d?d?d, literals
# allowed), never through a shell — but it still must not be able to look
# like another CLI flag (e.g. "--session=evil") to hashcat's own parser.
MASK_PATTERN = re.compile(r"^(?!-)[\x21-\x7e]{1,64}$")
# zip2john doesn't need the whole archive in memory to build the hash, but
# we buffer the full upload before writing it out (same tradeoff the LSASS
# dump decoder makes), so this caps memory use rather than being a format
# limit.
ZIP_MAX_BYTES = 300 * 1024 * 1024
# zip2john's own delimiters are asterisks, not colons, so the hash body
# never contains a bare ':' — matching between the $pkzip$/$zip2$ markers
# lets us pull the hash out of its "name:hash:::archive:entry" wrapper line
# without having to parse that wrapper.
ZIP_HASH_PATTERN = re.compile(r"\$(zip2|pkzip)\$.*?\$/\1\$")


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def job_directory(project: Project, target: Target, job_id: int) -> Path:
    path = (WORKSPACE_DIR / "projects" / _safe(project.name) / "targets" /
            _safe(target.ip) / "hash-cracking" / str(job_id))
    path.mkdir(parents=True, exist_ok=True)
    return path


@router.get("/catalog")
def get_catalog():
    return {
        "hash_modes": catalog.HASH_MODES,
        "wordlists": catalog.wordlists(),
        "rules": catalog.rules(),
        "hashcat_installed": bool(shutil.which("hashcat")),
    }


@router.post("/zip2john")
async def zip2john(file: UploadFile = File(...)):
    """Runs zip2john against an uploaded password-protected zip so the hash
    can flow straight into the job form below instead of requiring a
    separate terminal. Covers both legacy ZipCrypto ($pkzip$, the common
    `zip -e` case) and WinZip AES ($zip2$) archives — whichever zip2john
    emits decides which catalog hash mode gets pre-selected."""
    binary = shutil.which("zip2john")
    if not binary:
        raise HTTPException(409, "zip2john is not installed (part of the 'john' package)")
    content = await file.read(ZIP_MAX_BYTES + 1)
    if len(content) > ZIP_MAX_BYTES:
        raise HTTPException(413, f"Zip exceeds the {ZIP_MAX_BYTES // (1024 * 1024)}MB limit")
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / "upload.zip"
        zip_path.write_bytes(content)
        try:
            completed = subprocess.run([binary, str(zip_path)], capture_output=True,
                                       text=True, timeout=60, check=False)
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "zip2john timed out after 60 seconds")
    hash_lines = list(dict.fromkeys(m.group(0) for m in ZIP_HASH_PATTERN.finditer(completed.stdout)))
    if not hash_lines:
        detail = "zip2john extracted no crackable hash from this archive"
        if completed.stderr.strip():
            detail += f": {completed.stderr.strip()[:500]}"
        raise HTTPException(422, detail)
    hash_mode_id = "winzip" if hash_lines[0].startswith("$zip2$") else "pkzip"
    return {
        "hashes": "\n".join(hash_lines), "hash_mode_id": hash_mode_id,
        "stderr": completed.stderr[:5_000],
    }


@router.get("", response_model=list[JobOut])
def jobs(project_id: int | None = None, target_id: int | None = None,
         db: Session = Depends(get_db)):
    statement = select(HashCrackJob).order_by(HashCrackJob.id.desc())
    if project_id:
        statement = statement.where(HashCrackJob.project_id == project_id)
    if target_id:
        statement = statement.where(HashCrackJob.target_id == target_id)
    return db.scalars(statement.limit(200)).all()


@router.get("/{job_id}", response_model=JobOut)
def job(job_id: int, db: Session = Depends(get_db)):
    return need(db, HashCrackJob, job_id)


def _resolved_wordlist(wordlist_id: str, label: str) -> str:
    path = catalog.wordlist_path(wordlist_id) if wordlist_id else None
    if not path:
        raise HTTPException(400, f"Unknown or uninstalled {label}")
    return path


def _resolved_mask(mask: str) -> str:
    if not mask or not MASK_PATTERN.fullmatch(mask):
        raise HTTPException(400, "A valid hashcat mask is required for this attack mode")
    return mask


@router.post("", response_model=JobOut, status_code=201)
def create_job(body: JobIn, db: Session = Depends(get_db)):
    target = need(db, Target, body.target_id) if body.target_id else None
    if not target:
        raise HTTPException(400, "target_id is required")
    project = need(db, Project, body.project_id)
    if target.project_id != project.id:
        raise HTTPException(400, "Target does not belong to the project")
    hash_mode = catalog.HASH_MODE_INDEX.get(body.hash_mode_id)
    if not hash_mode:
        raise HTTPException(400, "Unknown hash_mode_id")
    hash_lines = [catalog.to_hashcat_line(hash_mode["id"], line)
                  for line in body.hashes.splitlines() if line.strip()]
    if not hash_lines:
        raise HTTPException(400, "No hash lines were provided")

    argv = ["hashcat", "-m", hash_mode["mode"], "-a", body.attack_mode,
            "--potfile-disable", "-o", "cracked.txt", "hashes.txt"]
    wordlist_id = wordlist2_id = rule_id = mask = ""
    if body.attack_mode == "0":
        wordlist_id = body.wordlist_id
        argv.append(_resolved_wordlist(wordlist_id, "wordlist_id"))
        if body.rule_id:
            rule_path = catalog.rule_path(body.rule_id)
            if not rule_path:
                raise HTTPException(400, "Unknown or uninstalled rule_id")
            rule_id = body.rule_id
            argv += ["-r", rule_path]
    elif body.attack_mode == "1":
        wordlist_id, wordlist2_id = body.wordlist_id, body.wordlist2_id
        argv.append(_resolved_wordlist(wordlist_id, "wordlist_id"))
        argv.append(_resolved_wordlist(wordlist2_id, "wordlist2_id"))
    elif body.attack_mode == "3":
        mask = _resolved_mask(body.mask)
        argv.append(mask)
    elif body.attack_mode == "6":
        wordlist_id, mask = body.wordlist_id, _resolved_mask(body.mask)
        argv.append(_resolved_wordlist(wordlist_id, "wordlist_id"))
        argv.append(mask)
    else:  # "7"
        wordlist_id, mask = body.wordlist_id, _resolved_mask(body.mask)
        argv.append(mask)
        argv.append(_resolved_wordlist(wordlist_id, "wordlist_id"))

    row = HashCrackJob(
        project_id=project.id, target_id=target.id, label=body.label,
        hash_mode_id=hash_mode["id"], hash_mode=hash_mode["mode"],
        hash_type_name=hash_mode["name"], attack_mode=body.attack_mode,
        wordlist_id=wordlist_id, wordlist2_id=wordlist2_id, rule_id=rule_id,
        mask=mask, hash_count=len(hash_lines))
    db.add(row); db.flush()
    folder = job_directory(project, target, row.id)
    hashes_path = folder / "hashes.txt"
    hashes_path.write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
    row.argv_json = json.dumps(argv)
    row.command_display = " ".join(argv)
    db.commit(); db.refresh(row)
    return row


@router.post("/{job_id}/start", response_model=JobOut, status_code=202)
async def start_job(job_id: int, db: Session = Depends(get_db)):
    row = need(db, HashCrackJob, job_id)
    if row.status != "prepared":
        raise HTTPException(409, "This job was already started")
    if not shutil.which("hashcat"):
        raise HTTPException(409, "hashcat is not installed (sudo apt install hashcat)")
    target = need(db, Target, row.target_id)
    project = need(db, Project, row.project_id)
    folder = job_directory(project, target, row.id)
    row.status = "running"; row.started_at = utcnow()
    db.commit(); db.refresh(row)
    manager.enqueue(row.id, json.loads(row.argv_json), folder)
    return row


@router.post("/{job_id}/cancel")
async def cancel_job(job_id: int, db: Session = Depends(get_db)):
    row = need(db, HashCrackJob, job_id)
    if row.status == "prepared":
        row.status = "cancelled"; row.cancelled = True
        db.commit()
        return {"cancelled": True}
    return {"cancelled": await manager.cancel(job_id)}


@router.get("/{job_id}/output")
def output(job_id: int, db: Session = Depends(get_db)):
    row = need(db, HashCrackJob, job_id)
    target = need(db, Target, row.target_id)
    project = need(db, Project, row.project_id)
    folder = job_directory(project, target, row.id)

    def read(path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    return {
        "stdout": read(folder / "stdout.txt"), "stderr": read(folder / "stderr.txt"),
        "cracked": parse_cracked(folder / "cracked.txt"),
    }


@router.get("/{job_id}/events")
async def events(job_id: int, db: Session = Depends(get_db)):
    row = need(db, HashCrackJob, job_id)
    target = need(db, Target, row.target_id)
    project = need(db, Project, row.project_id)
    folder = job_directory(project, target, row.id)
    queue = manager.subscribe(job_id)
    stdout_path, stderr_path = folder / "stdout.txt", folder / "stderr.txt"

    async def stream():
        try:
            if row.status in ("running", "prepared"):
                if stdout_path.is_file():
                    data = stdout_path.read_bytes()[-manager.stream_limit:].decode(errors="replace")
                    if stderr_path.is_file() and stderr_path.stat().st_size:
                        data += "\n[stderr]\n" + stderr_path.read_bytes()[
                            -manager.stream_limit:].decode(errors="replace")
                    yield f"data: {json.dumps({'stream': 'snapshot', 'data': data})}\n\n"
            yield f"data: {json.dumps({'stream': 'status', 'status': row.status, 'exit_code': row.exit_code, 'error': row.error})}\n\n"
            if row.status in ("completed", "failed", "cancelled"):
                return
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=10)
                except asyncio.TimeoutError:
                    process = manager.processes.get(job_id)
                    item = {"stream": "heartbeat", "status": "running",
                            "process_alive": bool(process and process.returncode is None)}
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("status") in ("completed", "failed", "cancelled"):
                    break
        finally:
            manager.unsubscribe(job_id, queue)
    return StreamingResponse(stream(), media_type="text/event-stream")


@router.post("/{job_id}/promote", status_code=201)
def promote(job_id: int, body: PromoteIn, db: Session = Depends(get_db)):
    row = need(db, HashCrackJob, job_id)
    credential = Credential(
        project_id=row.project_id, target_id=row.target_id,
        username=body.username.strip(), secret_kind="password", secret=body.secret,
        source_kind="hash_crack", source_detail=f"Hash crack #{row.id} · {row.hash_type_name}",
        domain=body.domain, service_names="[]", notes=body.notes)
    db.add(credential); db.commit(); db.refresh(credential)
    return {
        "id": credential.id, "project_id": credential.project_id,
        "target_id": credential.target_id, "username": credential.username,
        "secret_kind": credential.secret_kind, "domain": credential.domain,
    }
