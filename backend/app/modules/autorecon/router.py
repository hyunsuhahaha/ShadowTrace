import asyncio
from functools import lru_cache
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import AutoReconRun, Project, ScanJob, Target
from ...schemas import AutoReconRunIn, AutoReconRunOut
from ..core.support import need
from .manager import manager
from .service import render_autorecon_command, run_output_dir

TERMINAL_STATUSES = {"completed", "failed", "stopped", "interrupted"}

router = APIRouter(prefix="/api/autorecon", tags=["AutoRecon"])


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
            entries.append({"path": path.relative_to(root).as_posix(),
                            "is_dir": path.is_dir(),
                            "size": 0 if path.is_dir() else stat.st_size})
    return {"job_id": job.id, "run_id": run.id, "root": str(root),
            "entries": entries}


@router.get("/results/{job_id}/download")
def download_result(job_id: int, path: str, db: Session = Depends(get_db)):
    _, _, root = _result_context(db, job_id)
    root = root.resolve()
    candidate = (root / path).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        raise HTTPException(404, "Result file not found")
    return FileResponse(candidate, filename=candidate.name,
                        media_type="application/octet-stream")


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
