import asyncio
import json
import shutil
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import AutoReconRun, Project, Target
from ...schemas import AutoReconRunIn, AutoReconRunOut
from ..core.support import need
from .manager import manager
from .service import render_autorecon_command, run_output_dir

TERMINAL_STATUSES = {"completed", "failed", "stopped", "interrupted"}

router = APIRouter(prefix="/api/autorecon", tags=["AutoRecon"])


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
    row = AutoReconRun(project_id=project.id, target_ids=json.dumps(body.target_ids),
                       status="queued")
    db.add(row); db.commit(); db.refresh(row)
    output_dir = run_output_dir(project, row.id)
    output_dir.mkdir(parents=True, exist_ok=True)
    argv = render_autorecon_command(targets, output_dir)
    row.command = " ".join(argv)
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
