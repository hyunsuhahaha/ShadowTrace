import asyncio, json, os, pwd, re, shutil, subprocess
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, WebSocket
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete as sql_delete, select
from sqlalchemy.orm import Session
from .config import CONFIG_DIR, WORKSPACE_DIR
from .database import Base, SessionLocal, ensure_compatible_schema, get_db
from .executor import (
    processes as execution_processes, queues, reconcile_completed_observations, run_execution,
    shutdown_executions, stop_execution,
)
from .models import (
    AppSetting, AuditEvent, Execution, InteractiveSession, Project, Service,
    ServiceObservation, Target, Tunnel,
)
from .nmap_parser import parse_nmap
from .product_policy import public_policy
from .modules.scan_center.router import router as scan_router
from .modules.web_testing.router import router as web_router
from .modules.evidence.router import router as evidence_router
from .modules.directory.router import router as directory_router
from .modules.tunnels.router import manager as tunnel_manager, router as tunnel_router
from .modules.reports.router import router as report_router
from .modules.findings.router import router as finding_router
from .modules.operations.router import router as operations_router
from .modules.vpn import router as vpn_router, vpn_status
from .modules.privesc_server import (
    kill_orphaned_server, router as privesc_server_router,
    stop_privesc_server,
)
from .modules.exploit_research.router import (
    router as exploit_research_router, shutdown_local_runs,
)
from .modules.runbooks.router import router as runbook_router
from .modules.service_intelligence.router import router as service_intelligence_router
from .modules.runbooks.builtins import ensure_builtin_runbooks
from .modules.scan_center.manager import manager as scan_manager, recover_interrupted_jobs
from .schemas import (
    ExecutionIn, ExecutionOut, InteractiveSessionIn, InteractiveSessionOut,
    ManualTerminalIn, MetasploitLockIn, ProjectIn, ProjectOut, ServiceOut,
    ServiceUpdate, TargetEnsureIn, TargetIn, TargetOut,
)
from .templates import catalog
from .time import utcnow
from .pty_manager import pty_manager
import shlex

REPOSITORY_DIR = Path(__file__).resolve().parents[2]

if hasattr(os, "geteuid") and os.geteuid() == 0 and (
        os.getenv("OSCP_ALLOW_ROOT") != "1"
        or os.getenv("OSCP_BACKEND_BIND") != "127.0.0.1"):
    raise RuntimeError("Root backend requires the loopback-only launcher")
ensure_compatible_schema()

@asynccontextmanager
async def lifespan(_: FastAPI):
    with SessionLocal() as db:
        ensure_builtin_runbooks(db)
        setting=db.get(AppSetting,"scan_concurrency")
        if setting:
            scan_manager.set_concurrency(int(setting.value))
    recover_interrupted_jobs()
    kill_orphaned_server()
    with SessionLocal() as db:
        for row in db.query(Execution).filter(
                Execution.status.in_(("queued","running"))):
            row.status="interrupted";row.error="Application restarted";row.ended_at=utcnow()
        for model in (InteractiveSession,Tunnel):
            for row in db.query(model).filter(model.status.in_(("running","stopping"))):
                row.status="interrupted";row.error="Application restarted"
                row.ended_at=utcnow();row.pid=None
        db.commit()
        reconcile_completed_observations(db)
    yield
    await scan_manager.shutdown()
    await shutdown_executions()
    await pty_manager.shutdown()
    await tunnel_manager.shutdown()
    shutdown_local_runs()
    stop_privesc_server()

app = FastAPI(title="OSCP Workspace", version="0.1.0", lifespan=lifespan)
app.include_router(scan_router)
app.include_router(web_router)
app.include_router(evidence_router)
app.include_router(directory_router)
app.include_router(tunnel_router)
app.include_router(report_router)
app.include_router(finding_router)
app.include_router(operations_router)
app.include_router(vpn_router)
app.include_router(privesc_server_router)
app.include_router(exploit_research_router)
app.include_router(runbook_router)
app.include_router(service_intelligence_router)

@app.middleware("http")
async def mutation_audit(request:Request, call_next):
    response=await call_next(request)
    if request.url.path.startswith("/api"):
        # 404/410 are heuristically cacheable per RFC 9110 without an explicit
        # header, so a browser can keep replaying a stale error (e.g. a
        # since-recreated project's transient 410) long after the server has
        # moved on. API responses are never static assets, so never cache them.
        response.headers["Cache-Control"]="no-store"
    if request.method in {"POST","PUT","PATCH","DELETE"}:
        try:
            with SessionLocal() as db:
                db.add(AuditEvent(method=request.method,path=request.url.path[:2000],
                                  status_code=response.status_code))
                db.commit()
        except Exception:
            pass
    return response

@app.get("/api/product/capabilities")
def product_capabilities():
    """Expose the immutable OSCP+ product boundary to every client."""
    return public_policy()

def safe_part(value: str):
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in value).strip("._")
    if not cleaned: raise HTTPException(400, "Unsafe path component")
    return cleaned[:120]
def need(db, cls, ident):
    row = db.get(cls, ident)
    if not row: raise HTTPException(404, "Not found")
    return row

@app.get("/api/projects", response_model=list[ProjectOut])
def projects(db: Session = Depends(get_db)): return db.scalars(select(Project)).all()
@app.post("/api/projects", response_model=ProjectOut, status_code=201)
def create_project(body: ProjectIn, db: Session = Depends(get_db)):
    row=Project(**body.model_dump()); db.add(row); db.commit(); db.refresh(row); return row
@app.put("/api/projects/{ident}", response_model=ProjectOut)
def update_project(ident:int, body:ProjectIn, db:Session=Depends(get_db)):
    row=need(db,Project,ident)
    for k,v in body.model_dump().items(): setattr(row,k,v)
    db.commit(); return row
@app.put("/api/projects/{ident}/metasploit-lock", response_model=ProjectOut)
def set_metasploit_lock(ident:int, body:MetasploitLockIn, db:Session=Depends(get_db)):
    # OSCP exam rules allow Metasploit/Meterpreter against only one target for
    # the whole exam; this records that commitment so the UI can warn before
    # a second target gets used. It does not gate any execution itself.
    project=need(db,Project,ident)
    if body.target_id is not None:
        target=need(db,Target,body.target_id)
        if target.project_id!=ident:
            raise HTTPException(400,"Target does not belong to this project")
    project.metasploit_target_id=body.target_id
    project.metasploit_locked_at=utcnow() if body.target_id is not None else None
    db.commit(); db.refresh(project); return project
@app.delete("/api/projects/{ident}", status_code=204)
def delete_project(ident:int, db:Session=Depends(get_db)):
    project=need(db,Project,ident)
    tables=Base.metadata.tables
    target_ids=list(db.scalars(
        select(tables["targets"].c.id).where(
            tables["targets"].c.project_id == ident)))
    service_ids=list(db.scalars(
        select(tables["services"].c.id).where(
            tables["services"].c.target_id.in_(target_ids)))) if target_ids else []
    scan_ids=list(db.scalars(
        select(tables["scan_jobs"].c.id).where(
            tables["scan_jobs"].c.project_id == ident)))
    request_ids=list(db.scalars(
        select(tables["http_requests"].c.id).where(
            tables["http_requests"].c.project_id == ident)))
    research_ids=list(db.scalars(
        select(tables["exploit_research"].c.id).where(
            tables["exploit_research"].c.project_id == ident)))
    runbook_instance_ids=list(db.scalars(
        select(tables["runbook_instances"].c.id).where(
            tables["runbook_instances"].c.project_id == ident)))
    runbook_step_ids=list(db.scalars(
        select(tables["runbook_step_instances"].c.id).where(
            tables["runbook_step_instances"].c.instance_id.in_(
                runbook_instance_ids)))) if runbook_instance_ids else []
    credential_ids=list(db.scalars(
        select(tables["credentials"].c.id).where(
            tables["credentials"].c.project_id == ident)))
    finding_ids=list(db.scalars(
        select(tables["findings"].c.id).where(
            tables["findings"].c.project_id == ident)))
    evidence_ids=list(db.scalars(
        select(tables["evidence"].c.id).where(
            tables["evidence"].c.project_id == ident)))

    active = db.scalar(select(tables["scan_jobs"].c.id).where(
        tables["scan_jobs"].c.project_id == ident,
        tables["scan_jobs"].c.status.in_(["queued", "running", "processing"])))
    if active:
        raise HTTPException(409, "실행 중인 스캔을 중단한 뒤 프로젝트를 삭제하세요.")

    def remove(table_name: str, column: str, values: list[int]):
        if values:
            table=tables[table_name]
            db.execute(sql_delete(table).where(table.c[column].in_(values)))

    # Runbook and finding records are not ORM children of Project. Remove their
    # dependency graph explicitly so deleted project IDs cannot be reused by
    # SQLite and make historical runbooks appear under a new target.
    remove("runbook_step_evidence", "step_id", runbook_step_ids)
    remove("runbook_step_executions", "step_id", runbook_step_ids)
    remove("runbook_step_credentials", "step_id", runbook_step_ids)
    remove("finding_evidence", "finding_id", finding_ids)
    remove("finding_assets", "finding_id", finding_ids)
    remove("finding_retests", "finding_id", finding_ids)
    remove("findings", "id", finding_ids)
    remove("runbook_observations", "step_id", runbook_step_ids)
    remove("runbook_activity_events", "instance_id", runbook_instance_ids)
    remove("runbook_step_instances", "id", runbook_step_ids)
    remove("runbook_instances", "id", runbook_instance_ids)
    remove("runbook_recommendation_dismissals", "service_id", service_ids)
    remove("credentials", "id", credential_ids)
    remove("evidence_image_edits", "evidence_id", evidence_ids)
    remove("exploit_local_runs", "research_id", research_ids)
    remove("exploit_execution_records", "research_id", research_ids)
    remove("exploit_modifications", "research_id", research_ids)
    remove("exploit_sources", "research_id", research_ids)
    remove("http_exchanges", "request_id", request_ids)
    remove("scan_artifacts", "scan_job_id", scan_ids)
    remove("host_observations", "scan_job_id", scan_ids)
    remove("service_observations", "scan_job_id", scan_ids)
    db.execute(sql_delete(tables["directory_relations"]).where(
        tables["directory_relations"].c.project_id == ident))
    for table_name in [
        "evidence", "exploit_research", "http_requests", "directory_objects",
        "tunnels", "reports", "scan_jobs",
    ]:
        db.execute(sql_delete(tables[table_name]).where(
            tables[table_name].c.project_id == ident))
    for table_name in ["executions", "interactive_sessions"]:
        remove(table_name, "target_id", target_ids)
    remove("services", "id", service_ids)
    remove("targets", "id", target_ids)
    db.delete(project)
    db.commit()

@app.get("/api/targets", response_model=list[TargetOut])
def targets(project_id:int|None=None, db:Session=Depends(get_db)):
    stmt=select(Target)
    if project_id: stmt=stmt.where(Target.project_id==project_id)
    return db.scalars(stmt).all()
@app.post("/api/targets", response_model=TargetOut, status_code=201)
def create_target(body:TargetIn, db:Session=Depends(get_db)):
    need(db,Project,body.project_id); row=Target(**body.model_dump()); db.add(row); db.commit(); db.refresh(row); return row
@app.post("/api/targets/ensure", response_model=TargetOut)
def ensure_target(body:TargetEnsureIn, db:Session=Depends(get_db)):
    existing=db.scalar(select(Target).where(Target.ip==body.ip))
    if existing:return existing
    project=db.scalar(select(Project).where(Project.name==body.ip))
    if not project:
        project=Project(name=body.ip,description="")
        db.add(project);db.flush()
    row=Target(project_id=project.id,name=body.name or body.ip,ip=body.ip,
               hostname="",os_guess="",vpn="tun0",notes="")
    db.add(row);db.commit();db.refresh(row);return row
@app.put("/api/targets/{ident}", response_model=TargetOut)
def update_target(ident:int, body:TargetIn, db:Session=Depends(get_db)):
    row=need(db,Target,ident)
    for k,v in body.model_dump().items(): setattr(row,k,v)
    row.updated_at=utcnow(); db.commit(); return row
@app.delete("/api/targets/{ident}", status_code=204)
def delete_target(ident:int, db:Session=Depends(get_db)):
    db.delete(need(db,Target,ident)); db.commit()

@app.get("/api/targets/{ident}/services", response_model=list[ServiceOut])
def services(ident:int, db:Session=Depends(get_db)):
    need(db,Target,ident); return db.scalars(select(Service).where(Service.target_id==ident)).all()
@app.patch("/api/services/{ident}", response_model=ServiceOut)
def update_service(ident:int, body:ServiceUpdate, db:Session=Depends(get_db)):
    row=need(db,Service,ident)
    if body.product is not None:
        row.product=body.product.strip()
    if body.version is not None:
        row.version=body.version.strip()
    row.notes=body.notes
    row.tags=json.dumps(list(dict.fromkeys(tag.strip() for tag in body.tags if tag.strip())),
                        ensure_ascii=False)
    db.commit(); db.refresh(row); return row
@app.post("/api/targets/{ident}/nmap")
async def import_nmap(ident:int, file:UploadFile=File(...), db:Session=Depends(get_db)):
    from .modules.scan_center.service import import_xml as import_scan_xml
    target=need(db,Target,ident); project=need(db,Project,target.project_id)
    try:
        content=await file.read(10*1024*1024+1)
        job=import_scan_xml(db,target,project,content,file.filename or "nmap.xml")
    except Exception as exc:
        raise HTTPException(400, f"Invalid Nmap XML: {exc}")
    count=len(db.scalars(select(ServiceObservation).where(ServiceObservation.scan_job_id==job.id)).all())
    return {"scan_id":job.id,"hosts":1,"services":count}

@app.get("/api/services/{ident}/commands")
def commands(ident:int, db:Session=Depends(get_db)):
    service=need(db,Service,ident); target=need(db,Target,service.target_id)
    project=need(db,Project,target.project_id)
    target_dir=WORKSPACE_DIR/"projects"/safe_part(project.name)/"targets"/safe_part(target.ip)
    variables={"host":target.ip,"port":str(service.port),"protocol":service.protocol,
               "scheme":"https" if service.name=="https" else "http",
               "output_dir":str(target_dir/"outputs"),
               "repo_dir":str(REPOSITORY_DIR)}
    result=[]
    for item in catalog.commands_for(
            service.name, service.port, service.protocol,
            product=service.product, cpe=json.loads(service.cpe or "[]"),
            tls=service.tls):
        try: preview=catalog.render(
            item["id"], variables, item.get("execution_mode", "captured"))[1]
        except ValueError: preview=item["command"]
        result.append({**item,"preview":preview})
    return result

@app.get("/api/targets/{ident}/identity-commands")
def target_identity_commands(ident:int, db:Session=Depends(get_db)):
    target=need(db,Target,ident); project=need(db,Project,target.project_id)
    target_dir=WORKSPACE_DIR/"projects"/safe_part(project.name)/"targets"/safe_part(target.ip)
    variables={"host":target.ip,"output_dir":str(target_dir/"outputs")}
    result=[]
    for template_id in ("target-hostname-identity", "target-os-identity"):
        item=catalog.items.get(template_id)
        if not item:
            raise HTTPException(500, "Target identity command is not configured")
        try:
            preview=catalog.render(item["id"],variables)[1]
        except ValueError as exc:
            raise HTTPException(500, str(exc))
        result.append({**item,"preview":preview,"target_level":True})
    return result

@app.get("/api/executions", response_model=list[ExecutionOut])
def executions(target_id:int|None=None, db:Session=Depends(get_db)):
    stmt=select(Execution).order_by(Execution.id.desc())
    if target_id: stmt=stmt.where(Execution.target_id==target_id)
    return db.scalars(stmt.limit(100)).all()
@app.post("/api/executions", response_model=ExecutionOut, status_code=201)
async def execute(body:ExecutionIn, db:Session=Depends(get_db)):
    target=need(db,Target,body.target_id); service=need(db,Service,body.service_id) if body.service_id else None
    project=need(db,Project,target.project_id)
    target_dir=WORKSPACE_DIR/"projects"/safe_part(project.name)/"targets"/safe_part(target.ip)
    output_dir=target_dir/"outputs"; output_dir.mkdir(parents=True,exist_ok=True)
    variables={**body.variables,"host":target.ip,"target_dir":str(target_dir),
               "project_dir":str(target_dir.parents[1]),"output_dir":str(output_dir),
               "repo_dir":str(REPOSITORY_DIR)}
    if service: variables.update(port=str(service.port),protocol=service.protocol,
                                  scheme="https" if service.name=="https" else "http")
    item,command,argv=catalog.render(body.template_id,variables)
    if not shutil.which(argv[0]): raise HTTPException(409,f"Tool not installed: {argv[0]}")
    if body.run_as_root:
        if not shutil.which("sudo"): raise HTTPException(409,"sudo is not installed")
        argv=["sudo","-n",*argv]; command=shlex.join(argv)
    row=Execution(target_id=target.id,service_id=body.service_id,template_id=item["id"],
                  command=command,cwd=str(target_dir),status="queued")
    db.add(row); db.commit(); db.refresh(row)
    out=output_dir/f"{datetime.now():%Y%m%d_%H%M%S}_{safe_part(item['id'])}.txt"
    queues[row.id]=asyncio.Queue(); asyncio.create_task(run_execution(row.id,argv,target_dir,out))
    return row
@app.get("/api/executions/{ident}/output")
def execution_output(ident:int, download:bool=False, db:Session=Depends(get_db)):
    row=need(db,Execution,ident)
    if download and row.output_path:
        path=Path(row.output_path)
        if not path.is_file(): raise HTTPException(410,"Output file is no longer available")
        return FileResponse(path,filename=path.name,media_type="text/plain")
    return {"stdout":row.stdout,"stderr":row.stderr,"status":row.status,
            "error":row.error,"exit_code":row.exit_code}
@app.get("/api/executions/{ident}/events")
async def events(ident:int):
    queue=queues.setdefault(ident,asyncio.Queue())
    async def stream():
        while True:
            try:
                item=await asyncio.wait_for(queue.get(),timeout=10)
            except asyncio.TimeoutError:
                process=execution_processes.get(ident)
                item={"stream":"heartbeat","status":"running",
                      "process_alive":bool(process and process.returncode is None)}
            yield f"data: {json.dumps(item)}\n\n"
            if item.get("stream")=="status": break
    return StreamingResponse(stream(),media_type="text/event-stream")
@app.post("/api/executions/{ident}/stop")
async def stop(ident:int):
    return {"stopped":await stop_execution(ident)}

@app.get("/api/interactive-sessions", response_model=list[InteractiveSessionOut])
def interactive_sessions(target_id:int|None=None, db:Session=Depends(get_db)):
    stmt=select(InteractiveSession).order_by(InteractiveSession.id.desc())
    if target_id: stmt=stmt.where(InteractiveSession.target_id==target_id)
    return db.scalars(stmt.limit(100)).all()

@app.post("/api/interactive-sessions", response_model=InteractiveSessionOut,
          status_code=201)
def create_interactive_session(body:InteractiveSessionIn,
                               db:Session=Depends(get_db)):
    target=need(db,Target,body.target_id)
    service=need(db,Service,body.service_id) if body.service_id else None
    project=need(db,Project,target.project_id)
    if "password" in body.variables:
        raise HTTPException(400,"Passwords must be entered interactively")
    if (body.template_id == "smb-share-client"
            and not re.fullmatch(r"[^/\\\\\x00]{1,80}",
                                 body.variables.get("share", ""))):
        raise HTTPException(400, "Invalid SMB share name")
    target_dir=WORKSPACE_DIR/"projects"/safe_part(project.name)/"targets"/safe_part(target.ip)
    target_dir.mkdir(parents=True,exist_ok=True)
    variables={**body.variables,"host":target.ip,"repo_dir":str(REPOSITORY_DIR)}
    if service:
        variables.update(port=str(service.port),protocol=service.protocol,
                         scheme="https" if service.name=="https" else "http")
    try:
        item,command,argv=catalog.render(body.template_id,variables,"interactive")
    except ValueError as exc:
        raise HTTPException(400,str(exc))
    if not shutil.which(argv[0]):
        raise HTTPException(409,f"Tool not installed: {argv[0]}")
    if body.run_as_root:
        if not shutil.which("sudo"):
            raise HTTPException(409,"sudo is not installed")
        argv=["sudo",*argv]; command=shlex.join(argv)
    row=InteractiveSession(target_id=target.id,service_id=body.service_id,
        template_id=item["id"],command=command,cwd=str(target_dir),status="ready")
    db.add(row);db.commit();db.refresh(row);return row

@app.post("/api/interactive-sessions/manual",
          response_model=InteractiveSessionOut, status_code=201)
def create_manual_terminal(body: ManualTerminalIn,
                           db: Session = Depends(get_db)):
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
        cwd=str(target_dir), status="ready")
    db.add(row); db.commit(); db.refresh(row)
    return row

@app.websocket("/api/interactive-sessions/{ident}/ws")
async def interactive_session_socket(websocket:WebSocket,ident:int):
    with SessionLocal() as db:
        row=db.get(InteractiveSession,ident)
        if not row or row.status!="ready":
            await websocket.close(code=4409);return
        argv=shlex.split(row.command);cwd=Path(row.cwd)
        log_path=cwd/"outputs"/f"session_{row.id}.log"
        log_path.parent.mkdir(parents=True,exist_ok=True)
    await pty_manager.connect(ident,argv,cwd,log_path,websocket)

def anonymous_ftp_command(host: str, port: int) -> list[str]:
    return [
        "/usr/bin/env", "FTPANONPASS=IEUser@", "ftp", "-a", host, str(port),
    ]


@app.post("/api/interactive-sessions/{ident}/desktop",
          response_model=InteractiveSessionOut)
def launch_interactive_session_in_desktop(
        ident: int, ftp_anonymous: bool = False,
        db: Session = Depends(get_db)):
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
            raise HTTPException(400, "Anonymous auto-login is only available for FTP")
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
            ["/usr/sbin/runuser", "-u", owner.pw_name, "--", *desktop_env,
             terminal, "-w", row.cwd, "-e", shell_command],
            start_new_session=True, close_fds=True,
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

@app.post("/api/interactive-sessions/{ident}/stop")
async def stop_interactive_session(ident:int):
    return {"stopped":await pty_manager.stop(ident)}

@app.get("/api/interactive-sessions/{ident}/log")
def interactive_session_log(ident:int, db:Session=Depends(get_db)):
    row=need(db,InteractiveSession,ident);path=Path(row.log_path)
    if not row.log_path or not path.is_file():
        raise HTTPException(410,"Session log is not available")
    return FileResponse(path,filename=path.name,media_type="text/plain")

TOOLS={"nmap":"sudo apt install nmap","curl":"sudo apt install curl","wget":"sudo apt install wget",
"whatweb":"sudo apt install whatweb","gobuster":"sudo apt install gobuster","feroxbuster":"sudo apt install feroxbuster",
"nikto":"sudo apt install nikto","smbclient":"sudo apt install smbclient","enum4linux-ng":"sudo apt install enum4linux-ng",
"netexec":"sudo apt install netexec","rpcclient":"sudo apt install smbclient","dig":"sudo apt install dnsutils",
"snmpwalk":"sudo apt install snmp","showmount":"sudo apt install nfs-common","ftp":"sudo apt install ftp",
"ssh":"sudo apt install openssh-client","searchsploit":"sudo apt install exploitdb",
"hydra":"sudo apt install hydra","smbget":"sudo apt install smbclient",
"impacket-psexec":"sudo apt install python3-impacket","impacket-mssqlclient":"sudo apt install python3-impacket",
"evil-winrm":"sudo apt install evil-winrm","xfreerdp":"sudo apt install freerdp2-x11",
"hashcat":"sudo apt install hashcat"}
@app.get("/api/system/status")
def status():
    tools=[{"name":k,"installed":bool(p:=shutil.which(k)),"path":p,"install":v} for k,v in TOOLS.items()]
    def cmd(*args):
        try:return subprocess.run(args,capture_output=True,text=True,timeout=2).stdout
        except Exception:return ""
    return {"tools":tools,"vpn":vpn_status()}

dist=Path(__file__).parents[2]/"frontend"/"dist"
if dist.exists():
    app.mount("/assets",StaticFiles(directory=dist/"assets"),name="assets")
    @app.get("/{path:path}")
    def spa(path:str):
        candidate=(dist/path).resolve()
        if candidate.is_file() and dist.resolve() in candidate.parents:return FileResponse(candidate)
        return FileResponse(dist/"index.html")
