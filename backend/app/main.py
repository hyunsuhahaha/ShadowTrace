import asyncio, json, os, shutil, subprocess
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, WebSocket
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import WORKSPACE_DIR
from .database import Base, SessionLocal, engine, ensure_compatible_schema, get_db
from .executor import queues, run_execution, stop_execution
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
from .modules.operations.router import router as operations_router
from .modules.scan_center.manager import manager as scan_manager, recover_interrupted_jobs
from .schemas import (
    ExecutionIn, ExecutionOut, InteractiveSessionIn, InteractiveSessionOut,
    ProjectIn, ProjectOut, ServiceOut, ServiceUpdate, TargetIn, TargetOut,
)
from .templates import catalog
from .time import utcnow
from .pty_manager import pty_manager
import shlex

if hasattr(os, "geteuid") and os.geteuid() == 0 and os.getenv("OSCP_ALLOW_ROOT") != "1":
    raise RuntimeError("Refusing to run as root")
Base.metadata.create_all(engine)
ensure_compatible_schema()

@asynccontextmanager
async def lifespan(_: FastAPI):
    with SessionLocal() as db:
        setting=db.get(AppSetting,"scan_concurrency")
        if setting:
            scan_manager.set_concurrency(int(setting.value))
    recover_interrupted_jobs()
    with SessionLocal() as db:
        for row in db.query(Execution).filter(
                Execution.status.in_(("queued","running"))):
            row.status="interrupted";row.error="Application restarted";row.ended_at=utcnow()
        for model in (InteractiveSession,Tunnel):
            for row in db.query(model).filter(model.status.in_(("running","stopping"))):
                row.status="interrupted";row.error="Application restarted"
                row.ended_at=utcnow();row.pid=None
        db.commit()
    yield
    await scan_manager.shutdown()
    await pty_manager.shutdown()
    await tunnel_manager.shutdown()

app = FastAPI(title="OSCP Workspace", version="0.1.0", lifespan=lifespan)
app.include_router(scan_router)
app.include_router(web_router)
app.include_router(evidence_router)
app.include_router(directory_router)
app.include_router(tunnel_router)
app.include_router(report_router)
app.include_router(operations_router)

@app.middleware("http")
async def mutation_audit(request:Request, call_next):
    response=await call_next(request)
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
@app.delete("/api/projects/{ident}", status_code=204)
def delete_project(ident:int, db:Session=Depends(get_db)):
    db.delete(need(db,Project,ident)); db.commit()

@app.get("/api/targets", response_model=list[TargetOut])
def targets(project_id:int|None=None, db:Session=Depends(get_db)):
    stmt=select(Target)
    if project_id: stmt=stmt.where(Target.project_id==project_id)
    return db.scalars(stmt).all()
@app.post("/api/targets", response_model=TargetOut, status_code=201)
def create_target(body:TargetIn, db:Session=Depends(get_db)):
    need(db,Project,body.project_id); row=Target(**body.model_dump()); db.add(row); db.commit(); db.refresh(row); return row
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
    row=need(db,Service,ident); row.notes=body.notes
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
    variables={"host":target.ip,"port":str(service.port),"protocol":service.protocol,
               "scheme":"https" if service.name=="https" else "http"}
    result=[]
    for item in catalog.commands_for(service.name,service.port):
        try: preview=catalog.render(item["id"],variables)[1]
        except ValueError: preview=item["command"]
        result.append({**item,"preview":preview})
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
               "project_dir":str(target_dir.parents[1]),"output_dir":str(output_dir)}
    if service: variables.update(port=str(service.port),protocol=service.protocol,
                                  scheme="https" if service.name=="https" else "http")
    item,command,argv=catalog.render(body.template_id,variables)
    if not shutil.which(argv[0]): raise HTTPException(409,f"Tool not installed: {argv[0]}")
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
            item=await queue.get()
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
    target_dir=WORKSPACE_DIR/"projects"/safe_part(project.name)/"targets"/safe_part(target.ip)
    target_dir.mkdir(parents=True,exist_ok=True)
    variables={**body.variables,"host":target.ip}
    if service:
        variables.update(port=str(service.port),protocol=service.protocol,
                         scheme="https" if service.name=="https" else "http")
    try:
        item,command,argv=catalog.render(body.template_id,variables,"interactive")
    except ValueError as exc:
        raise HTTPException(400,str(exc))
    if not shutil.which(argv[0]):
        raise HTTPException(409,f"Tool not installed: {argv[0]}")
    row=InteractiveSession(target_id=target.id,service_id=body.service_id,
        template_id=item["id"],command=command,cwd=str(target_dir),status="ready")
    db.add(row);db.commit();db.refresh(row);return row

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
"snmpwalk":"sudo apt install snmp","showmount":"sudo apt install nfs-common","ftp":"sudo apt install ftp","ssh":"sudo apt install openssh-client"}
@app.get("/api/system/status")
def status():
    tools=[{"name":k,"installed":bool(p:=shutil.which(k)),"path":p,"install":v} for k,v in TOOLS.items()]
    def cmd(*args):
        try:return subprocess.run(args,capture_output=True,text=True,timeout=2).stdout
        except Exception:return ""
    addr=cmd("ip","-brief","addr","show","tun0"); route=cmd("ip","route")
    return {"tools":tools,"vpn":{"connected":bool(addr),"tun0":addr.strip(),"routes":route.splitlines()[:8]}}

dist=Path(__file__).parents[2]/"frontend"/"dist"
if dist.exists():
    app.mount("/assets",StaticFiles(directory=dist/"assets"),name="assets")
    @app.get("/{path:path}")
    def spa(path:str):
        candidate=(dist/path).resolve()
        if candidate.is_file() and dist.resolve() in candidate.parents:return FileResponse(candidate)
        return FileResponse(dist/"index.html")
