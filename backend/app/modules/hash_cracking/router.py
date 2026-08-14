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
# A legacy ZipCrypto ($pkzip$) hash's own leading field is how many of the
# archive's files it bundles into this one hash line -- an archive with
# more than one encrypted member (backup.zip with index.php AND style.css,
# say) produces a single $pkzip$2*... line, and mode 17200 ("PKZIP
# (Compressed)", single-file only) rejects that outright with "Hash-value
# exception" (confirmed live: hashcat --identify agrees 17220 is what a
# 2-file hash actually is). $pkzip$ itself never distinguishes "compressed"
# from "mixed" compression across members the way 17220 vs 17225 do --
# 17220 is the correct guess whenever it's uniform, which is what `zip -e`
# (and most real-world tooling) always produces, so that's the fallback;
# the dropdown is manually correctable if a given archive turns out mixed.
PKZIP_COUNT = re.compile(r"^\$pkzip\$(\d+)\*")


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
        "john_installed": bool(shutil.which("john")),
    }


def run_zip2john(content: bytes) -> dict:
    """Runs zip2john against a password-protected zip's raw bytes so the
    hash can flow straight into the job form below instead of requiring a
    separate terminal. Covers both legacy ZipCrypto ($pkzip$, the common
    `zip -e` case) and WinZip AES ($zip2$) archives — whichever zip2john
    emits decides which catalog hash mode gets pre-selected. Shared by the
    upload endpoint below and evidence's own zip2john handoff (an evidence
    row already has the archive on disk, no re-upload needed)."""
    binary = shutil.which("zip2john")
    if not binary:
        raise HTTPException(409, "zip2john is not installed (part of the 'john' package)")
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
    if hash_lines[0].startswith("$zip2$"):
        hash_mode_id = "winzip"
    else:
        count_match = PKZIP_COUNT.match(hash_lines[0])
        hash_mode_id = "pkzip_multi_compressed" if count_match and int(count_match.group(1)) > 1 \
            else "pkzip"
    return {
        "hashes": "\n".join(hash_lines), "hash_mode_id": hash_mode_id,
        "stderr": completed.stderr[:5_000],
    }


@router.post("/zip2john")
async def zip2john(file: UploadFile = File(...)):
    content = await file.read(ZIP_MAX_BYTES + 1)
    return run_zip2john(content)


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

    john_format = hash_mode.get("john_format")
    if body.engine == "john" and not john_format:
        raise HTTPException(
            400, f"john engine doesn't support hash mode '{hash_mode['id']}' yet -- pick hashcat")
    if body.engine == "john" and body.attack_mode not in ("0", "3"):
        raise HTTPException(400, "john engine only supports dictionary (0) or mask (3) attacks")
    if body.engine == "john" and body.rule_id:
        raise HTTPException(400, "john engine doesn't support hashcat rule files")

    wordlist_id = wordlist2_id = rule_id = mask = ""
    if body.engine == "john":
        argv = ["john", f"--format={john_format}"]
        if body.attack_mode == "0":
            wordlist_id = body.wordlist_id
            argv.append(f"--wordlist={_resolved_wordlist(wordlist_id, 'wordlist_id')}")
        else:  # "3"
            mask = _resolved_mask(body.mask)
            argv.append(f"--mask={mask}")
        argv.append("hashes.txt")
    else:
        argv = ["hashcat", "-m", hash_mode["mode"], "-a", body.attack_mode,
                "--potfile-disable", "-o", "cracked.txt", "hashes.txt"]
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
        project_id=project.id, target_id=target.id, label=body.label, engine=body.engine,
        hash_mode_id=hash_mode["id"], hash_mode=hash_mode["mode"],
        hash_type_name=hash_mode["name"], attack_mode=body.attack_mode,
        wordlist_id=wordlist_id, wordlist2_id=wordlist2_id, rule_id=rule_id,
        mask=mask, hash_count=len(hash_lines), graph_parent_node_id=body.graph_node_id)
    db.add(row); db.flush()
    if body.engine == "john":
        # john has no hashcat-style single-instance lock (concurrent jobs
        # don't collide the way hashcat's do), but still gets its own
        # --session name for isolated restore-state bookkeeping.
        argv[1:1] = [f"--session={row.id}"]
    else:
        # Without an explicit --session, every job shares hashcat's default
        # session name and its single-instance lock file with it -- a second
        # job started while an earlier one is still running fails instantly
        # with "Already an instance '/usr/bin/hashcat' running", regardless of
        # which job/hashes/target it's actually for (confirmed live: two
        # concurrent jobs on unrelated hashes collided this way). Job id is
        # unique per row, so using it as the session name gives every job its
        # own lock.
        argv[6:6] = ["--session", str(row.id)]  # after the fixed base, before the mode-specific tail
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
    if not shutil.which(row.engine):
        raise HTTPException(409, f"{row.engine} is not installed")
    target = need(db, Target, row.target_id)
    project = need(db, Project, row.project_id)
    folder = job_directory(project, target, row.id)
    row.status = "running"; row.started_at = utcnow()
    db.commit(); db.refresh(row)
    manager.enqueue(row.id, json.loads(row.argv_json), folder, row.engine,
                    catalog.HASH_MODE_INDEX[row.hash_mode_id].get("john_format", ""))
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
    credential = db.get(Credential, body.credential_id) if body.credential_id else None
    if body.credential_id:
        if credential is None:
            raise HTTPException(404, "credential not found")
        if credential.project_id != row.project_id or credential.target_id != row.target_id:
            raise HTTPException(400, "Credential belongs to another hash cracking scope")
        credential.secret_kind = "password"
        credential.secret = body.secret
        credential.secret_hint = f"Cracked from {row.hash_type_name}"
        credential.source_execution_kind = "hash_crack_job"
        credential.source_execution_id = row.id
        if body.notes:
            credential.notes = "\n".join(filter(None, (credential.notes, body.notes)))
    else:
        if not body.username.strip():
            raise HTTPException(422, "username is required without credential_id")
        credential = Credential(
            project_id=row.project_id, target_id=row.target_id,
            username=body.username.strip(), secret_kind="password", secret=body.secret,
            source_kind="hash_crack", source_detail=f"Hash crack #{row.id} · {row.hash_type_name}",
            source_execution_kind="hash_crack_job", source_execution_id=row.id,
            domain=body.domain, service_names="[]", notes=body.notes)
        db.add(credential)
    db.commit(); db.refresh(credential)
    return {
        "id": credential.id, "project_id": credential.project_id,
        "target_id": credential.target_id, "username": credential.username,
        "secret_kind": credential.secret_kind, "domain": credential.domain,
    }
