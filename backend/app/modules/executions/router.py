import asyncio
import hashlib
import json
import re
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
from ...models import Evidence, Execution, Project, Service, Target
from ...schemas import ExecutionDeriveIn, ExecutionIn, ExecutionOut, EvidenceOut
from ...templates import catalog
from ..core.support import need, safe_part

router = APIRouter()
REPOSITORY_DIR = Path(__file__).resolve().parents[4]
SHELL_OPERATORS = {"|", "||", "&&", ";", ">", ">>", "<", "<<"}


def _bound_value_count(argv: list[str], value: str, numeric: bool = False) -> int:
    if not value:
        return 0
    pattern = re.compile(
        rf"(?<!\d){re.escape(value)}(?!\d)" if numeric else re.escape(value)
    )
    return sum(len(pattern.findall(argument)) for argument in argv)


def _validated_override(
    raw: str, base_argv: list[str], host: str, service: Service | None,
    context_values: tuple[str, ...] = (),
) -> tuple[str, list[str]]:
    try:
        argv = shlex.split(raw.strip())
    except ValueError as exc:
        raise HTTPException(400, f"Invalid command syntax: {exc}") from exc
    if not argv:
        raise HTTPException(400, "Command cannot be empty")
    if any(argument in SHELL_OPERATORS or re.match(r"^\d*(?:>|<)", argument)
           for argument in argv):
        raise HTTPException(400, "Shell operators require a separate shell session")
    if Path(argv[0]).name != Path(base_argv[0]).name:
        raise HTTPException(400, "ENGINE CHANGED · EXECUTION LOCKED")
    for value in {host, *context_values}:
        if _bound_value_count(argv, value) < _bound_value_count(base_argv, value):
            raise HTTPException(400, "TARGET CHANGED · EXECUTION LOCKED")
    if service:
        port = str(service.port)
        if (_bound_value_count(argv, port, numeric=True)
                < _bound_value_count(base_argv, port, numeric=True)):
            raise HTTPException(400, "SERVICE CHANGED · EXECUTION LOCKED")
    return raw.strip(), argv


def _output_path(output_dir: Path, raw_filename: str, template_id: str) -> Path:
    if not raw_filename.strip():
        return output_dir / f"{datetime.now():%Y%m%d_%H%M%S}_{safe_part(template_id)}.txt"
    base = safe_part(raw_filename.strip())
    if base.lower().endswith(".txt"):
        base = base[:-4] or "output"
    candidate = output_dir / f"{base}.txt"
    counter = 2
    while candidate.exists():
        candidate = output_dir / f"{base}-{counter}.txt"
        counter += 1
    return candidate


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
    if service and service.target_id != target.id:
        raise HTTPException(400, "Service does not belong to target")
    project = need(db, Project, target.project_id)
    target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                  "targets" / safe_part(target.ip))
    output_dir = target_dir / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)
    # Sites that route by vhost (nearly all named HTTP hosts) refuse or
    # redirect requests addressed by bare IP, so HTTP-family commands need
    # the confirmed hostname once one exists — everything else (SMB, LDAP,
    # RDP...) keeps hitting the IP directly since a hostname mismatch there
    # is far less likely to change the response.
    template = catalog.items.get(body.template_id)
    use_hostname = (
        target.hostname and template and template.get("service_key") == "http"
    )
    variables = {
        **body.variables,
        "host": target.hostname if use_hostname else target.ip,
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
    if body.command_override is not None:
        command, argv = _validated_override(
            body.command_override, argv, variables["host"], service, (target.ip,),
        )
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
    output = _output_path(output_dir, body.output_filename, item["id"])
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


@router.delete("/api/executions/{ident}", status_code=204)
def delete_execution(ident: int, db: Session = Depends(get_db)):
    row = need(db, Execution, ident)
    if row.status in ("queued", "running"):
        raise HTTPException(409, "Stop the command before deleting it")
    if row.output_path:
        Path(row.output_path).unlink(missing_ok=True)
    db.delete(row)
    db.commit()


def _execution_output_dir(db: Session, execution: Execution) -> tuple[Target, Path]:
    target = need(db, Target, execution.target_id)
    project = need(db, Project, target.project_id)
    target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                  "targets" / safe_part(target.ip))
    return target, target_dir / "outputs"


@router.get("/api/executions/{ident}/file")
def execution_output_file(ident: int, name: str, db: Session = Depends(get_db)):
    """Read a file a command wrote directly into the target's output folder
    (e.g. impacket-GetNPUsers' -outputfile), separate from the execution's
    own stdout/stderr capture."""
    execution = need(db, Execution, ident)
    _, output_dir = _execution_output_dir(db, execution)
    path = output_dir / safe_part(name)
    if not path.is_file():
        raise HTTPException(404, "Output file not found")
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        raise HTTPException(404, "Output file not found")
    return {"name": path.name, "content": content}


@router.post("/api/executions/{ident}/derive", response_model=EvidenceOut,
            status_code=201)
def derive_output(ident: int, body: ExecutionDeriveIn, db: Session = Depends(get_db)):
    execution = need(db, Execution, ident)
    target, output_dir = _execution_output_dir(db, execution)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _output_path(output_dir, body.filename, f"{execution.template_id}-derived")
    content = body.content.encode("utf-8")
    path.write_bytes(content)
    row = Evidence(
        project_id=target.project_id, target_id=target.id,
        service_id=execution.service_id,
        title=f"{execution.template_id} 결과 · {path.name}",
        description=f"실행 #{execution.id} 결과에서 추출한 값: {execution.command}",
        kind="command_output", source_type="execution", source_id=execution.id,
        file_path=str(path), original_name=path.name,
        sha256=hashlib.sha256(content).hexdigest(), size=len(content),
        hostname=target.hostname or target.ip, include_report=False,
        tags=json.dumps(["auto-captured", "derived", execution.template_id],
                        ensure_ascii=False),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
