import asyncio
import os
import pwd
import re
import shlex
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import CONFIG_DIR, WORKSPACE_DIR
from ...database import SessionLocal, get_db
from ...executor import queues, run_execution
from ...models import Execution, InteractiveSession, Project, Service, Target
from ...pty_manager import pty_manager
from ...schemas import (
    DesktopLaunchIn,
    InteractiveSessionIn,
    InteractiveSessionOut,
    ManualTerminalIn,
)
from ...templates import catalog
from ...time import utcnow
from ..core.support import need, safe_part
from ..executions.router import _output_path

router = APIRouter()
REPOSITORY_DIR = Path(__file__).resolve().parents[4]
TYPE_RELAY_SCRIPT = Path(__file__).resolve().parent / "type_relay.exp"


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
    command = body.command.strip() or f"{shell} --noprofile --norc"
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid command syntax: {exc}") from exc
    if not argv or not shutil.which(argv[0]):
        raise HTTPException(409, f"Tool not installed: {argv[0] if argv else command}")
    if body.run_as_root:
        if not shutil.which("sudo"):
            raise HTTPException(409, "sudo is not installed")
        command = shlex.join(["sudo", *argv])
    row = InteractiveSession(
        target_id=target.id, service_id=service.id,
        template_id="manual-shell", command=command,
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


async def _auto_run_ftp_tree(target_id: int, service_id: int) -> None:
    # ftp-directory-tree's script doubles as the login check (a wrong
    # password fails before any listing starts), so an anonymous crawl here
    # is safe to fire for every way an ftp-client session gets opened --
    # not just the anonymous-exposure and typed-credential paths the
    # frontend already wires up -- since this endpoint is the one choke
    # point all of them launch a desktop session through.
    with SessionLocal() as db:
        target = db.get(Target, target_id)
        service = db.get(Service, service_id)
        if not target or not service:
            return
        project = db.get(Project, target.project_id)
        target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                      "targets" / safe_part(target.ip))
        output_dir = target_dir / "outputs"
        output_dir.mkdir(parents=True, exist_ok=True)
        variables = {
            "host": target.ip, "port": str(service.port), "username": "", "password": "",
            "target_dir": str(target_dir), "project_dir": str(target_dir.parents[1]),
            "output_dir": str(output_dir), "repo_dir": str(REPOSITORY_DIR),
        }
        item, command, argv = catalog.render("ftp-directory-tree", variables)
        if not shutil.which(argv[0]):
            return
        row = Execution(target_id=target.id, service_id=service.id,
                         template_id=item["id"], command=command, cwd=str(target_dir),
                         status="queued")
        db.add(row); db.commit(); db.refresh(row)
        output = _output_path(output_dir, "", item["id"])
        execution_id = row.id
    queues[execution_id] = asyncio.Queue()
    await run_execution(execution_id, argv, target_dir, output)


def anonymous_ftp_command(host: str, port: int) -> list[str]:
    return [
        "/usr/bin/env", "FTPANONPASS=IEUser@", "ftp", "-a", host, str(port),
    ]


def _deliver_secret_to_fifo(fifo_path: Path, secret: str) -> None:
    # type_relay.exp only opens this fifo for reading once it has already
    # matched the spawned program's password prompt, so this blocks (via a
    # bounded poll, since a plain blocking open() here has no timeout of its
    # own) until that happens -- or gives up if it never does, e.g. the
    # prompt text didn't match within the script's own timeout.
    fd = None
    deadline = time.monotonic() + 12
    try:
        while fd is None and time.monotonic() < deadline:
            try:
                fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:
                time.sleep(0.2)
        if fd is not None:
            os.write(fd, f"{secret}\n".encode())
    finally:
        if fd is not None:
            os.close(fd)
        fifo_path.unlink(missing_ok=True)


@router.post(
    "/api/interactive-sessions/{ident}/desktop",
    response_model=InteractiveSessionOut,
)
def launch_interactive_session_in_desktop(
    ident: int,
    background_tasks: BackgroundTasks,
    ftp_anonymous: bool = False,
    body: DesktopLaunchIn = DesktopLaunchIn(),
    db: Session = Depends(get_db),
):
    row = need(db, InteractiveSession, ident)
    if row.status != "ready":
        raise HTTPException(409, "Session is not ready")
    terminal = shutil.which("qterminal") or shutil.which("x-terminal-emulator")
    if not terminal:
        raise HTTPException(409, "Kali desktop terminal is not installed")
    if body.type_after and not shutil.which("expect"):
        raise HTTPException(409, "expect가 설치되어 있지 않습니다 (비밀번호 자동 입력에 필요)")
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
    shell = owner.pw_shell or "/usr/bin/zsh"
    fifo_path: Path | None = None
    if body.type_after:
        fifo_path = Path(f"/tmp/.oscp-wr-{uuid.uuid4().hex}")
        os.mkfifo(fifo_path, 0o600)
        os.chown(fifo_path, owner.pw_uid, owner.pw_gid)
        # expect gives the spawned command a real pty (via /bin/sh -c, so
        # the already shell-quoted `command` string is re-parsed the same
        # way it always was), which is what makes this work for prompts
        # that refuse a plain piped/redirected stdin -- the secret itself
        # only ever passes through the fifo above, never this argv.
        command = shlex.join([
            "expect", str(TYPE_RELAY_SCRIPT), str(fifo_path), "/bin/sh", "-c", command,
        ])
    inner_command = f"{command}; exec {shell} -l"
    try:
        process = subprocess.Popen(
            [
                # qterminal's -e does not re-parse a single joined string
                # through a shell -- it needs the shell, its flags, and the
                # command as separate argv items, or any command containing
                # its own quoting (e.g. a shlex-quoted username) breaks
                # apart into garbage and the shell exits immediately.
                "/usr/sbin/runuser", "-u", owner.pw_name, "--", *desktop_env,
                terminal, "-w", row.cwd, "-e", shell, "-lic", inner_command,
            ],
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        if fifo_path:
            fifo_path.unlink(missing_ok=True)
        row.status = "failed"
        row.error = str(exc)
        row.ended_at = utcnow()
        db.commit()
        raise HTTPException(500, "데스크톱 터미널을 열지 못했습니다.") from exc
    if fifo_path:
        background_tasks.add_task(_deliver_secret_to_fifo, fifo_path, body.type_after)
    row.status = "launched"
    row.pid = process.pid
    row.started_at = utcnow()
    db.commit()
    db.refresh(row)
    if row.template_id == "ftp-client" and row.service_id:
        background_tasks.add_task(_auto_run_ftp_tree, row.target_id, row.service_id)
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


RESPONDER_LOGS_DIR = Path("/usr/share/responder/logs")


def _parse_responder_log(path: Path) -> list[dict]:
    """Each line Responder wrote is either `user:password` (a file whose
    name contains ClearText) or a hashcat/John-format `user::domain:...`
    hash string. Responder only ever writes the first capture of a given
    (module, type, client, user) combo to this file — later repeats of the
    same account print to the terminal (with -v) but never touch the file
    — so every line here is a genuinely distinct captured credential."""
    label = path.stem
    is_cleartext = "ClearText" in label
    try:
        lines = [line.strip() for line in
                 path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except OSError:
        return []
    captured_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    entries = []
    for line in lines:
        if is_cleartext:
            username, _, value = line.partition(":")
        else:
            parts = line.split(":")
            username = parts[0]
            value = line
        if not username:
            continue
        entries.append({
            "label": label, "username": username, "value": value,
            "cleartext": is_cleartext, "captured_at": captured_at,
        })
    return entries


@router.get("/api/targets/{ident}/responder-captures")
def responder_captures(ident: int, db: Session = Depends(get_db)):
    """Surface what Responder has already captured for this target directly
    in the app — the log files it writes to are the one authoritative,
    de-duplicated record, so this doesn't depend on catching the right
    moment in a separate desktop terminal or on Responder's own dedup
    deciding whether to print anything at all."""
    target = need(db, Target, ident)
    seen: set[tuple[str, str]] = set()
    results = []
    if RESPONDER_LOGS_DIR.is_dir():
        for path in sorted(RESPONDER_LOGS_DIR.glob(f"*-{target.ip}.txt")):
            # CaptureMultipleHashFromSameHost (on by default in this repo's
            # Responder.conf) appends every repeat authentication attempt,
            # not just the first — cracking any one of an account's hashes
            # yields the same password, so only the earliest (file order)
            # capture per account is worth surfacing here.
            for entry in _parse_responder_log(path):
                key = (entry["label"], entry["username"])
                if key in seen:
                    continue
                seen.add(key)
                results.append(entry)
    results.sort(key=lambda item: item["captured_at"], reverse=True)
    return results
