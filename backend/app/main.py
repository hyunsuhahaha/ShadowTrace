import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .database import SessionLocal, ensure_compatible_schema
from .executor import reconcile_completed_observations, shutdown_executions
from .models import (
    AppSetting, AuditEvent, Execution, HashCrackJob, InteractiveSession, RemoteExecution,
    Tunnel,
)
from .nmap_parser import parse_nmap
from .modules.scan_center.router import router as scan_router
from .modules.web_testing.router import router as web_router
from .modules.evidence.router import router as evidence_router
from .modules.directory.router import router as directory_router
from .modules.tunnels.router import manager as tunnel_manager, router as tunnel_router
from .modules.reports.router import router as report_router
from .modules.findings.router import router as finding_router
from .modules.operations.router import router as operations_router
from .modules.vpn import router as vpn_router
from .modules.system import router as system_router
from .modules.privesc_server import (
    kill_orphaned_server, router as privesc_server_router,
    stop_privesc_server,
)
from .modules.exploit_research.router import (
    router as exploit_research_router, shutdown_local_runs,
)
from .modules.runbooks.credentials_router import router as runbook_credentials_router
from .modules.runbooks.execution_router import router as runbook_execution_router
from .modules.runbooks.workflow_router import router as runbook_workflow_router
from .modules.service_intelligence.router import router as service_intelligence_router
from .modules.runbooks.builtins import ensure_builtin_runbooks
from .modules.scan_center.manager import manager as scan_manager, recover_interrupted_jobs
from .modules.web_proxy.router import router as web_proxy_router
from .modules.web_proxy.manager import manager as web_proxy_manager
from .modules.post_exploitation.router import router as post_exploitation_router
from .modules.post_exploitation.manager import manager as post_exploitation_manager
from .modules.hash_cracking.router import router as hash_cracking_router
from .modules.hash_cracking.manager import manager as hash_cracking_manager
from .modules.privesc_analysis.router import router as privesc_analysis_router
from .modules.decoders.router import router as decoders_router
from .modules.core.router import (
    delete_project,
    ensure_target,
    router as core_router,
    set_metasploit_lock,
    update_service,
)
from .modules.executions.router import router as execution_router
from .modules.sessions.router import (
    anonymous_ftp_command,
    router as session_router,
)
from .time import utcnow
from .pty_manager import pty_manager

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
        for row in db.query(RemoteExecution).filter(
                RemoteExecution.status.in_(("prepared","running"))):
            row.status="failed";row.error="Application restarted"
            row.ended_at=utcnow()
        for row in db.query(HashCrackJob).filter(
                HashCrackJob.status.in_(("prepared","running"))):
            row.status="failed";row.error="Application restarted"
            row.ended_at=utcnow()
        db.commit()
        reconcile_completed_observations(db)
    yield
    await scan_manager.shutdown()
    await shutdown_executions()
    await pty_manager.shutdown()
    await tunnel_manager.shutdown()
    await post_exploitation_manager.shutdown()
    await hash_cracking_manager.shutdown()
    await web_proxy_manager.shutdown()
    shutdown_local_runs()
    stop_privesc_server()

app = FastAPI(title="OSCP Workspace", version="0.1.0", lifespan=lifespan)
app.include_router(scan_router)
app.include_router(web_router)
app.include_router(web_proxy_router)
app.include_router(evidence_router)
app.include_router(directory_router)
app.include_router(tunnel_router)
app.include_router(report_router)
app.include_router(finding_router)
app.include_router(operations_router)
app.include_router(vpn_router)
app.include_router(privesc_server_router)
app.include_router(exploit_research_router)
app.include_router(runbook_workflow_router)
app.include_router(runbook_execution_router)
app.include_router(runbook_credentials_router)
app.include_router(service_intelligence_router)
app.include_router(post_exploitation_router)
app.include_router(hash_cracking_router)
app.include_router(privesc_analysis_router)
app.include_router(decoders_router)
app.include_router(core_router)
app.include_router(execution_router)
app.include_router(session_router)
app.include_router(system_router)

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

dist=Path(__file__).parents[2]/"frontend"/"dist"
if dist.exists():
    app.mount("/assets",StaticFiles(directory=dist/"assets"),name="assets")
    @app.get("/{path:path}")
    def spa(path:str):
        candidate=(dist/path).resolve()
        if candidate.is_file() and dist.resolve() in candidate.parents:return FileResponse(candidate)
        return FileResponse(dist/"index.html")
