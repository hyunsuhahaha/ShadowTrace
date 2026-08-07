import pwd
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import CONFIG_DIR, WORKSPACE_DIR
from ...database import SessionLocal, get_db
from ...models import InteractiveSession, Project, Service, Target
from ...pty_manager import pty_manager
from ...schemas import (
    InteractiveSessionIn,
    InteractiveSessionOut,
    ManualTerminalIn,
)
from ...templates import catalog
from ...time import utcnow
from ..core.support import need, safe_part

router = APIRouter()
REPOSITORY_DIR = Path(__file__).resolve().parents[4]


@router.get("/api/interactive-sessions", response_model=list[InteractiveSessionOut])
def interactive_sessions(
    target_id: int | None = None, db: Session = Depends(get_db)
):
    statement = select(InteractiveSession).order_by(InteractiveSession.id.desc())
    if target_id:
        statement = statement.where(InteractiveSession.target_id == target_id)
    return db.scalars(statement.limit(100)).all()


@router.post(
    "/api/interactive-sessions",
    response_model=InteractiveSessionOut,
    status_code=201,
)
def create_interactive_session(
    body: InteractiveSessionIn, db: Session = Depends(get_db)
):
    target = need(db, Target, body.target_id)
    service = need(db, Service, body.service_id) if body.service_id else None
    project = need(db, Project, target.project_id)
    if "password" in body.variables:
        raise HTTPException(400, "Passwords must be entered interactively")
    if (
        body.template_id == "smb-share-client"
        and not re.fullmatch(r"[^/\\\x00]{1,80}", body.variables.get("share", ""))
    ):
        raise HTTPException(400, "Invalid SMB share name")
    # Responder binds one interface's LLMNR/NBT-NS/SMB/etc ports exclusively,
    # so a second instance doesn't run alongside the first -- it just fails
    # to bind most of the same ports the first one already holds. Checking
    # the real process (not this app's own session bookkeeping, which never
    # learns a desktop-launched terminal closed) catches that before a
    # second window opens and immediately errors out.
    if body.template_id == "responder-listener":
        running = subprocess.run(
            ["pgrep", "-f", "Responder.py"], capture_output=True, text=True)
        if running.returncode == 0:
            raise HTTPException(
                409, "Responder가 이미 실행 중입니다 (PID "
                f"{running.stdout.split()[0]}). 기존 터미널 창을 사용하세요.")
    target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                  "targets" / safe_part(target.ip))
    target_dir.mkdir(parents=True, exist_ok=True)
    variables = {
        **body.variables,
        "host": target.ip,
        "repo_dir": str(REPOSITORY_DIR),
    }
    if service:
        variables.update(
            port=str(service.port), protocol=service.protocol,
            scheme="https" if service.name == "https" else "http",
        )
    try:
        item, command, argv = catalog.render(
            body.template_id, variables, "interactive"
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not shutil.which(argv[0]):
        raise HTTPException(409, f"Tool not installed: {argv[0]}")
    if body.run_as_root:
        if not shutil.which("sudo"):
            raise HTTPException(409, "sudo is not installed")
        argv = ["sudo", *argv]
        command = shlex.join(argv)
    row = InteractiveSession(
        target_id=target.id, service_id=body.service_id,
        template_id=item["id"], command=command, cwd=str(target_dir),
        status="ready",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.post(
    "/api/interactive-sessions/manual",
    response_model=InteractiveSessionOut,
    status_code=201,
)
def create_manual_terminal(
    body: ManualTerminalIn, db: Session = Depends(get_db)
):
    target = need(db, Target, body.target_id)
    service = need(db, Service, body.service_id)
    if service.target_id != target.id:
        raise HTTPException(400, "Service does not belong to target")
    project = need(db, Project, target.project_id)
    target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                  "targets" / safe_part(target.ip))
    target_dir.mkdir(parents=True, exist_ok=True)
    shell = "/bin/bash"
    if not Path(shell).is_file():
        raise HTTPException(409, "Local Bash shell is unavailable")
    row = InteractiveSession(
        target_id=target.id, service_id=service.id,
        template_id="manual-shell", command=f"{shell} --noprofile --norc",
        cwd=str(target_dir), status="ready",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.websocket("/api/interactive-sessions/{ident}/ws")
async def interactive_session_socket(websocket: WebSocket, ident: int):
    with SessionLocal() as db:
        row = db.get(InteractiveSession, ident)
        if not row or row.status != "ready":
            await websocket.close(code=4409)
            return
        argv = shlex.split(row.command)
        cwd = Path(row.cwd)
        log_path = cwd / "outputs" / f"session_{row.id}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
    await pty_manager.connect(ident, argv, cwd, log_path, websocket)


def anonymous_ftp_command(host: str, port: int) -> list[str]:
    return [
        "/usr/bin/env", "FTPANONPASS=IEUser@", "ftp", "-a", host, str(port),
    ]


@router.post(
    "/api/interactive-sessions/{ident}/desktop",
    response_model=InteractiveSessionOut,
)
def launch_interactive_session_in_desktop(
    ident: int,
    ftp_anonymous: bool = False,
    db: Session = Depends(get_db),
):
    row = need(db, InteractiveSession, ident)
    if row.status != "ready":
        raise HTTPException(409, "Session is not ready")
    terminal = shutil.which("qterminal") or shutil.which("x-terminal-emulator")
    if not terminal:
        raise HTTPException(409, "Kali desktop terminal is not installed")
    owner = pwd.getpwuid(CONFIG_DIR.stat().st_uid)
    desktop_env = [
        "/usr/bin/env",
        "DISPLAY=:0",
        f"XAUTHORITY={owner.pw_dir}/.Xauthority",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{owner.pw_uid}/bus",
        f"XDG_RUNTIME_DIR=/run/user/{owner.pw_uid}",
    ]
    command = row.command
    if ftp_anonymous:
        if row.template_id != "ftp-client" or not row.service_id:
            raise HTTPException(
                400, "Anonymous auto-login is only available for FTP"
            )
        target = need(db, Target, row.target_id)
        service = need(db, Service, row.service_id)
        command = shlex.join(anonymous_ftp_command(target.ip, service.port))
    shell_command = shlex.join([
        owner.pw_shell or "/usr/bin/zsh",
        "-lic",
        f"{command}; exec {owner.pw_shell or '/usr/bin/zsh'} -l",
    ])
    try:
        process = subprocess.Popen(
            [
                "/usr/sbin/runuser", "-u", owner.pw_name, "--", *desktop_env,
                terminal, "-w", row.cwd, "-e", shell_command,
            ],
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        row.status = "failed"
        row.error = str(exc)
        row.ended_at = utcnow()
        db.commit()
        raise HTTPException(500, "데스크톱 터미널을 열지 못했습니다.") from exc
    row.status = "launched"
    row.pid = process.pid
    row.started_at = utcnow()
    db.commit()
    db.refresh(row)
    return row


@router.post("/api/interactive-sessions/{ident}/stop")
async def stop_interactive_session(ident: int):
    return {"stopped": await pty_manager.stop(ident)}


@router.get("/api/interactive-sessions/{ident}/log")
def interactive_session_log(ident: int, db: Session = Depends(get_db)):
    row = need(db, InteractiveSession, ident)
    if not row.log_path:
        raise HTTPException(410, "Session log is not available")
    path = Path(row.log_path)
    if not path.is_file():
        raise HTTPException(410, "Session log is not available")
    return FileResponse(path, filename=path.name, media_type="text/plain")
