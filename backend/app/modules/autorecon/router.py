import asyncio
from functools import lru_cache
import hashlib
import json
import mimetypes
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import (AutoReconRun, Evidence, Finding, FindingEvidence, GraphNode,
                       Project, ScanJob, Target)
from ...schemas import AutoReconRunIn, AutoReconRunOut
from ..core.support import need
from ..graph import service as graph_service
from .manager import manager
from .service import render_autorecon_command, run_output_dir

TERMINAL_STATUSES = {"completed", "failed", "stopped", "interrupted"}

router = APIRouter(prefix="/api/autorecon", tags=["AutoRecon"])


class ResultFileIn(BaseModel):
    path: str = Field(min_length=1, max_length=2048)
    graph_node_id: str | None = Field(default=None, max_length=40)


def _parse_help_options(help_text: str) -> list[dict[str, str]]:
    options: list[dict[str, str]] = []
    seen: set[str] = set()
    current: dict[str, str] | None = None
    enabled = False
    for line in help_text.splitlines():
        if line.strip() in {"options:", "plugin arguments:", "global plugin arguments:"}:
            enabled = True
            current = None
            continue
        if not enabled:
            continue
        match = re.match(r"^\s{2,}(-{1,2}\S.*)$", line)
        if match:
            parts = re.split(r"\s{2,}", match.group(1).strip(), maxsplit=1)
            signature = parts[0]
            description = parts[1] if len(parts) > 1 else ""
            flags = re.findall(r"(?<!\S)-{1,2}[\w.-]+", signature)
            if not flags:
                current = None
                continue
            if flags[-1] in seen:
                current = None
                continue
            current = {"flag": flags[-1], "signature": signature.strip(),
                       "description": description.strip()}
            options.append(current)
            seen.add(flags[-1])
        elif current and line.startswith(" " * 20) and line.strip():
            current["description"] = f"{current['description']} {line.strip()}".strip()
        else:
            current = None
    return options


@lru_cache(maxsize=1)
def _installed_capabilities() -> dict:
    binary = shutil.which("autorecon")
    if not binary:
        return {"installed": False, "version": "", "help": "", "plugins": [],
                "options": []}
    def output(*args: str) -> str:
        result = subprocess.run([binary, *args], capture_output=True, text=True,
                                timeout=15, check=False)
        return (result.stdout + result.stderr).strip()
    help_text = output("--help")
    plugins = []
    pattern = re.compile(r"^(PortScan|ServiceScan|Report): (.+) \(([^)]+)\)(?: - (.*))?$")
    for line in output("--list").splitlines():
        match = pattern.match(line.strip())
        if match:
            plugins.append({"type": match.group(1), "name": match.group(2),
                            "slug": match.group(3), "description": match.group(4) or ""})
    return {"installed": True, "version": output("--version"),
            "help": help_text, "plugins": plugins,
            "options": _parse_help_options(help_text)}


@router.get("/capabilities")
def capabilities():
    return _installed_capabilities()


def _result_context(db: Session, job_id: int) -> tuple[ScanJob, AutoReconRun, Path]:
    job = need(db, ScanJob, job_id)
    if job.source != "autorecon":
        raise HTTPException(404, "AutoRecon result not found")
    run = db.scalar(select(AutoReconRun).where(
        AutoReconRun.project_id == job.project_id,
        AutoReconRun.command == job.command))
    target = db.get(Target, job.target_id)
    if run is None or target is None:
        raise HTTPException(404, "AutoRecon result not found")
    return job, run, Path(run.output_dir) / target.ip


def _result_file(db: Session, job_id: int, relative_path: str) -> tuple[ScanJob, Path]:
    job, _, root = _result_context(db, job_id)
    root = root.resolve()
    candidate = (root / relative_path).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        raise HTTPException(404, "Result file not found")
    return job, candidate


@router.get("/results/{job_id}")
def result_tree(job_id: int, db: Session = Depends(get_db)):
    job, run, root = _result_context(db, job_id)
    entries = []
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            try:
                stat = path.stat()
            except OSError:
                continue
            media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            entries.append({"path": path.relative_to(root).as_posix(),
                            "is_dir": path.is_dir(),
                            "size": 0 if path.is_dir() else stat.st_size,
                            "media_type": "inode/directory" if path.is_dir() else media_type})
    return {"job_id": job.id, "run_id": run.id, "root": str(root),
            "entries": entries}


@router.get("/results/{job_id}/download")
def download_result(job_id: int, path: str, db: Session = Depends(get_db)):
    _, candidate = _result_file(db, job_id, path)
    return FileResponse(candidate, filename=candidate.name,
                        media_type="application/octet-stream")


@router.get("/results/{job_id}/preview")
def preview_result(job_id: int, path: str, db: Session = Depends(get_db)):
    _, candidate = _result_file(db, job_id, path)
    media_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
    headers = {"X-Content-Type-Options": "nosniff",
               "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"}
    if media_type.startswith("image/") or media_type == "application/pdf":
        return FileResponse(candidate, media_type=media_type, headers=headers)
    if (media_type.startswith("text/") or candidate.suffix.lower() in
            {".log", ".nmap", ".gnmap", ".xml", ".json", ".yaml", ".yml", ".toml"}):
        content = candidate.read_bytes()[:2_000_000].decode(errors="replace")
        return PlainTextResponse(content, headers=headers)
    raise HTTPException(415, "This file type cannot be previewed safely")


@router.post("/results/{job_id}/promote", status_code=201)
def promote_result(job_id: int, body: ResultFileIn, db: Session = Depends(get_db)):
    job, candidate = _result_file(db, job_id, body.path)
    target = need(db, Target, job.target_id)
    content = candidate.read_bytes()
    evidence = Evidence(
        project_id=job.project_id, target_id=target.id,
        title=f"AutoRecon 파일: {body.path}",
        description=f"AutoRecon 결과 디렉터리에서 그래프로 배치 · ScanJob #{job.id}",
        kind="attachment", source_type="autorecon_scan", source_id=job.id,
        file_path=str(candidate), original_name=candidate.name,
        sha256=hashlib.sha256(content).hexdigest(), size=len(content),
        hostname=target.hostname or target.ip, include_report=False)
    db.add(evidence); db.flush()
    finding = Finding(
        project_id=job.project_id, target_id=target.id,
        title=f"AutoRecon 파일: {body.path}", status="Draft",
        reproduction_steps=f"AutoRecon 결과 경로: {body.path}")
    db.add(finding); db.flush()
    db.add(FindingEvidence(finding_id=finding.id, evidence_id=evidence.id, is_primary=True))
    source_node = db.get(GraphNode, body.graph_node_id) if body.graph_node_id else None
    if (source_node and source_node.project_id == job.project_id
            and source_node.type == "technique"):
        finding_node = graph_service.create_node(
            db, job.project_id, "finding", label=finding.title,
            source_ref=json.dumps({"module": "findings", "kind": "finding",
                                   "id": finding.id}, sort_keys=True),
            meta=json.dumps({"severity": finding.severity,
                             "category": finding.category, "evidenceCount": 1}))
        graph_service.create_edge(db, job.project_id, source_node.id,
                                  finding_node.id, "yielded", status="succeeded")
    db.commit()
    return {"finding_id": finding.id, "evidence_id": evidence.id}


@router.get("", response_model=list[AutoReconRunOut])
def runs(project_id: int | None = None, db: Session = Depends(get_db)):
    statement = select(AutoReconRun).order_by(AutoReconRun.id.desc())
    if project_id:
        statement = statement.where(AutoReconRun.project_id == project_id)
    return db.scalars(statement.limit(50)).all()


@router.get("/{run_id}", response_model=AutoReconRunOut)
def run(run_id: int, db: Session = Depends(get_db)):
    return need(db, AutoReconRun, run_id)


@router.post("/run", response_model=AutoReconRunOut, status_code=201)
async def start_run(body: AutoReconRunIn, db: Session = Depends(get_db)):
    if not shutil.which("autorecon"):
        raise HTTPException(409, "autorecon가 설치돼 있지 않습니다. "
            "pipx install git+https://github.com/Tib3rius/AutoRecon "
            "(PyPI의 동명 패키지는 무관한 다른 도구이니 주의)")
    project = need(db, Project, body.project_id)
    targets = [need(db, Target, target_id) for target_id in body.target_ids]
    for target in targets:
        if target.project_id != project.id:
            raise HTTPException(400, "Target does not belong to project")
    try:
        extra_args = shlex.split(body.arguments)
        render_autorecon_command(targets, Path("."), extra_args)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    row = AutoReconRun(project_id=project.id, target_ids=json.dumps(body.target_ids),
                       status="queued")
    db.add(row); db.commit(); db.refresh(row)
    output_dir = run_output_dir(project, row.id)
    output_dir.mkdir(parents=True, exist_ok=True)
    argv = render_autorecon_command(targets, output_dir, extra_args)
    row.command = shlex.join(argv)
    row.output_dir = str(output_dir)
    db.commit(); db.refresh(row)
    manager.enqueue(row.id, argv)
    return row


@router.get("/{run_id}/events")
async def run_events(run_id: int, db: Session = Depends(get_db)):
    run = need(db, AutoReconRun, run_id)
    queue = manager.subscribe(run_id)
    stdout_path = Path(run.output_dir) / "stdout.txt" if run.output_dir else None
    stderr_path = Path(run.output_dir) / "stderr.txt" if run.output_dir else None

    async def stream():
        try:
            # Replays everything captured so far as one "snapshot" event --
            # without this, reopening this panel (switching workspaces and
            # back, or just re-selecting the run) started a brand new
            # subscription with no history, so the transcript looked like it
            # had been wiped even though the run itself was still going.
            if stdout_path and stdout_path.is_file():
                data = stdout_path.read_bytes()[-manager.stream_limit:].decode(errors="replace")
                if stderr_path and stderr_path.is_file() and stderr_path.stat().st_size:
                    data += "\n[stderr]\n" + stderr_path.read_bytes()[
                        -manager.stream_limit:].decode(errors="replace")
                yield f"data: {json.dumps({'stream': 'snapshot', 'data': data})}\n\n"
            yield f"data: {json.dumps({'stream': 'status', 'status': run.status, 'exit_code': run.exit_code, 'error': run.error, 'imported_count': run.imported_count})}\n\n"
            if run.status in TERMINAL_STATUSES:
                return
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=10)
                except asyncio.TimeoutError:
                    process = manager.processes.get(run_id)
                    item = {"stream": "heartbeat",
                            "process_alive": bool(process and process.returncode is None)}
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("stream") == "status":
                    break
        finally:
            manager.unsubscribe(run_id, queue)

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.post("/{run_id}/stop")
async def stop_run(run_id: int, db: Session = Depends(get_db)):
    need(db, AutoReconRun, run_id)
    return {"stopped": await manager.stop(run_id)}
