from __future__ import annotations
import asyncio
import os
import shlex
import shutil
import signal
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...database import SessionLocal, get_db
from ...models import Project, Target, Tunnel
from ...schemas import TunnelIn, TunnelOut
from ...time import utcnow
from ..scan_center.service import _safe

router = APIRouter(prefix="/api/tunnels", tags=["Tunnels"])


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def render(body: TunnelIn) -> list[str]:
    if not body.confirmed:
        raise ValueError("Scope confirmation is required")
    if body.kind != "dynamic" and (not body.remote_host or not body.remote_port):
        raise ValueError("Remote host and port are required")
    destination = f"{body.username}@{body.ssh_host}"
    argv = ["ssh", "-N", "-o", "ExitOnForwardFailure=yes",
            "-o", "BatchMode=yes", "-p", str(body.ssh_port)]
    if body.kind == "local":
        argv += ["-L", f"{body.bind_host}:{body.local_port}:{body.remote_host}:{body.remote_port}"]
    elif body.kind == "remote":
        argv += ["-R", f"{body.bind_host}:{body.local_port}:{body.remote_host}:{body.remote_port}"]
    else:
        argv += ["-D", f"{body.bind_host}:{body.local_port}"]
    return [*argv, destination]


class TunnelManager:
    def __init__(self):
        self.processes: dict[int, asyncio.subprocess.Process] = {}
        self.tasks: dict[int, asyncio.Task] = {}

    def start(self, tunnel_id: int, argv: list[str], cwd: Path,
              log_path: Path) -> None:
        self.tasks[tunnel_id] = asyncio.create_task(
            self._run(tunnel_id, argv, cwd, log_path))

    async def _run(self, tunnel_id: int, argv: list[str], cwd: Path,
                   log_path: Path) -> None:
        try:
            with log_path.open("ab") as log:
                process = await asyncio.create_subprocess_exec(
                    *argv, cwd=cwd, stdout=log, stderr=log,
                    start_new_session=True)
                self.processes[tunnel_id] = process
                with SessionLocal() as db:
                    row = db.get(Tunnel, tunnel_id)
                    row.status = "running"; row.pid = process.pid
                    row.started_at = utcnow(); row.log_path = str(log_path); db.commit()
                code = await process.wait()
            with SessionLocal() as db:
                row = db.get(Tunnel, tunnel_id)
                row.status = "stopped" if row.status == "stopping" else (
                    "failed" if code else "completed")
                row.error = "" if code == 0 else f"ssh exited with code {code}"
                row.pid = None; row.ended_at = utcnow(); db.commit()
        except Exception as exc:
            with SessionLocal() as db:
                row = db.get(Tunnel, tunnel_id)
                if row:
                    row.status = "failed"; row.error = str(exc)
                    row.pid = None; row.ended_at = utcnow(); db.commit()
        finally:
            self.processes.pop(tunnel_id, None)
            self.tasks.pop(tunnel_id, None)

    async def stop(self, tunnel_id: int) -> bool:
        process = self.processes.get(tunnel_id)
        if not process or process.returncode is not None:
            return False
        with SessionLocal() as db:
            row = db.get(Tunnel, tunnel_id)
            row.status = "stopping"; db.commit()
        os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 3)
        except asyncio.TimeoutError:
            os.killpg(process.pid, signal.SIGKILL)
        return True

    async def shutdown(self):
        for tunnel_id in list(self.processes):
            await self.stop(tunnel_id)


manager = TunnelManager()


@router.get("", response_model=list[TunnelOut])
def tunnels(project_id: int | None = None, db: Session = Depends(get_db)):
    statement = select(Tunnel).order_by(Tunnel.id.desc())
    if project_id:
        statement = statement.where(Tunnel.project_id == project_id)
    return db.scalars(statement.limit(500)).all()


@router.post("", response_model=TunnelOut, status_code=201)
async def create_tunnel(body: TunnelIn, db: Session = Depends(get_db)):
    project = need(db, Project, body.project_id)
    target = need(db, Target, body.target_id)
    if target.project_id != project.id:
        raise HTTPException(400, "Target does not belong to the project")
    if not shutil.which("ssh"):
        raise HTTPException(409, "OpenSSH client is not installed")
    try:
        argv = render(body)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    values = body.model_dump(exclude={"confirmed"})
    row = Tunnel(**values, command=shlex.join(argv), status="ready")
    db.add(row); db.commit(); db.refresh(row)
    folder = (WORKSPACE_DIR / "projects" / _safe(project.name) / "targets" /
              _safe(target.ip) / "tunnels")
    folder.mkdir(parents=True, exist_ok=True)
    manager.start(row.id, argv, folder, folder / f"tunnel-{row.id}.log")
    return row


@router.post("/{ident}/stop")
async def stop_tunnel(ident: int, db: Session = Depends(get_db)):
    need(db, Tunnel, ident)
    return {"stopped": await manager.stop(ident)}


@router.get("/{ident}/log")
def tunnel_log(ident: int, db: Session = Depends(get_db)):
    row = need(db, Tunnel, ident)
    path = Path(row.log_path)
    if not row.log_path or not path.is_file():
        raise HTTPException(410, "Tunnel log is not available")
    return FileResponse(path, filename=path.name, media_type="text/plain")
