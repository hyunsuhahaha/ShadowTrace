import asyncio
import json
import shlex
import shutil
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import WORKSPACE_DIR
from ...database import get_db
from ...executor import (
    processes,
    queues,
    run_execution,
    stop_execution,
)
from ...models import Execution, Project, Service, Target
from ...schemas import ExecutionIn, ExecutionOut
from ...templates import catalog
from ..core.support import need, safe_part

router = APIRouter()
REPOSITORY_DIR = Path(__file__).resolve().parents[4]


@router.get("/api/executions", response_model=list[ExecutionOut])
def executions(target_id: int | None = None, db: Session = Depends(get_db)):
    statement = select(Execution).order_by(Execution.id.desc())
    if target_id:
        statement = statement.where(Execution.target_id == target_id)
    return db.scalars(statement.limit(100)).all()


@router.post("/api/executions", response_model=ExecutionOut, status_code=201)
async def execute(body: ExecutionIn, db: Session = Depends(get_db)):
    target = need(db, Target, body.target_id)
    service = need(db, Service, body.service_id) if body.service_id else None
    project = need(db, Project, target.project_id)
    target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                  "targets" / safe_part(target.ip))
    output_dir = target_dir / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)
    variables = {
        **body.variables,
        "host": target.ip,
        "target_dir": str(target_dir),
        "project_dir": str(target_dir.parents[1]),
        "output_dir": str(output_dir),
        "repo_dir": str(REPOSITORY_DIR),
    }
    if service:
        variables.update(
            port=str(service.port), protocol=service.protocol,
            scheme="https" if service.name == "https" else "http",
        )
    item, command, argv = catalog.render(body.template_id, variables)
    if not shutil.which(argv[0]):
        raise HTTPException(409, f"Tool not installed: {argv[0]}")
    if body.run_as_root:
        if not shutil.which("sudo"):
            raise HTTPException(409, "sudo is not installed")
        argv = ["sudo", "-n", *argv]
        command = shlex.join(argv)
    row = Execution(
        target_id=target.id, service_id=body.service_id,
        template_id=item["id"], command=command, cwd=str(target_dir),
        status="queued",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    output = output_dir / f"{datetime.now():%Y%m%d_%H%M%S}_{safe_part(item['id'])}.txt"
    queues[row.id] = asyncio.Queue()
    asyncio.create_task(run_execution(row.id, argv, target_dir, output))
    return row


@router.get("/api/executions/{ident}/output")
def execution_output(
    ident: int, download: bool = False, db: Session = Depends(get_db)
):
    row = need(db, Execution, ident)
    if download and row.output_path:
        path = Path(row.output_path)
        if not path.is_file():
            raise HTTPException(410, "Output file is no longer available")
        return FileResponse(path, filename=path.name, media_type="text/plain")
    return {
        "stdout": row.stdout, "stderr": row.stderr, "status": row.status,
        "error": row.error, "exit_code": row.exit_code,
    }


@router.get("/api/executions/{ident}/events")
async def events(ident: int):
    queue = queues.setdefault(ident, asyncio.Queue())

    async def stream():
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=10)
            except asyncio.TimeoutError:
                process = processes.get(ident)
                item = {
                    "stream": "heartbeat", "status": "running",
                    "process_alive": bool(process and process.returncode is None),
                }
            yield f"data: {json.dumps(item)}\n\n"
            if item.get("stream") == "status":
                break

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.post("/api/executions/{ident}/stop")
async def stop(ident: int):
    return {"stopped": await stop_execution(ident)}
