import asyncio
import json
import csv
import io
import shlex
import shutil
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import (
    AppSetting, Evidence, Finding, HostObservation, Project, ScanArtifact,
    ScanJob, ScanProfile, ServiceObservation, Target,
)
from ...schemas import (
    ObservationOut, ScanArtifactOut, ScanJobOut, ScanJobUpdate,
    ScanPreviewIn, ScanProfileOut, ScanSettings,
)
from .service import compare_jobs, import_xml, render_scan, scan_directory, seed_profiles
from .manager import manager

router = APIRouter(prefix="/api/scans", tags=["Scan Center"])

@router.get("/settings", response_model=ScanSettings)
def settings(db: Session = Depends(get_db)):
    row = db.get(AppSetting, "scan_concurrency")
    return {"concurrency": int(row.value) if row else 2}

@router.put("/settings", response_model=ScanSettings)
def update_settings(body: ScanSettings, db: Session = Depends(get_db)):
    try:
        manager.set_concurrency(body.concurrency)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    row = db.get(AppSetting, "scan_concurrency")
    if row:
        row.value = str(body.concurrency)
    else:
        db.add(AppSetting(key="scan_concurrency", value=str(body.concurrency)))
    db.commit()
    return body

def need(db: Session, cls, ident: int):
    row = db.get(cls, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row

@router.get("/profiles", response_model=list[ScanProfileOut])
def profiles(db: Session = Depends(get_db)):
    seed_profiles(db)
    return db.scalars(select(ScanProfile).order_by(ScanProfile.id)).all()


@router.get("/{ident}/automation")
def automation_summary(ident: int, db: Session = Depends(get_db)):
    need(db, ScanJob, ident)
    evidence = db.scalars(select(Evidence).where(
        Evidence.source_type == "scan", Evidence.source_id == ident)).all()
    marker = f"scan:{ident}:"
    findings = db.scalars(select(Finding).where(
        Finding.internal_notes.like(f"{marker}%"))).all()
    return {
        "evidence_count": len(evidence),
        "finding_count": len(findings),
        "finding_ids": [row.id for row in findings],
        "review_required": bool(findings),
    }

@router.post("/preview")
def preview(body: ScanPreviewIn, db: Session = Depends(get_db)):
    try:
        command, argv = render_scan(need(db, ScanProfile, body.profile_id),
                                    need(db, Target, body.target_id),
                                    body.ports, body.extra_arguments,
                                    body.top_ports)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"command": command, "argv": argv}

@router.post("/run", response_model=ScanJobOut, status_code=201)
async def run_scan(body: ScanPreviewIn, db: Session = Depends(get_db)):
    target, profile = need(db, Target, body.target_id), need(db, ScanProfile, body.profile_id)
    active = db.scalar(select(ScanJob.id).where(
        ScanJob.target_id == target.id,
        ScanJob.status.in_(("queued", "running"))))
    if active:
        raise HTTPException(409, "This target already has an active scan")
    try:
        command, argv = render_scan(
            profile, target, body.ports, body.extra_arguments, body.top_ports
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    binary = profile.engine or "nmap"
    if not shutil.which(binary):
        raise HTTPException(409, f"{binary.capitalize()} is not installed or is not on PATH")
    if argv[0] == "pkexec" and not shutil.which("pkexec"):
        raise HTTPException(409, "pkexec is required for this privileged scan")
    job = ScanJob(project_id=target.project_id, target_id=target.id,
                  profile_id=profile.id, source="executed", status="queued",
                  command=command)
    db.add(job); db.commit(); db.refresh(job)
    manager.enqueue(job.id, argv)
    return job

@router.get("/{scan_id}/events")
async def scan_events(scan_id: int, db: Session = Depends(get_db)):
    job = need(db, ScanJob, scan_id)
    queue = manager.subscribe(scan_id)
    stdout = db.scalar(select(ScanArtifact).where(
        ScanArtifact.scan_job_id == scan_id, ScanArtifact.kind == "stdout"))
    stderr = db.scalar(select(ScanArtifact).where(
        ScanArtifact.scan_job_id == scan_id, ScanArtifact.kind == "stderr"))
    stdout_path = __import__("pathlib").Path(stdout.path) if stdout else None
    stderr_path = __import__("pathlib").Path(stderr.path) if stderr else None
    if job.status in ("queued", "running"):
        folder = scan_directory(
            need(db, Project, job.project_id), need(db, Target, job.target_id),
            job.id)
        stdout_path = folder / "stdout.txt"
        stderr_path = folder / "stderr.txt"
    async def stream():
        try:
            if stdout_path and stdout_path.is_file():
                data = stdout_path.read_bytes()[-manager.stream_limit:].decode(errors="replace")
                if stderr_path and stderr_path.is_file() and stderr_path.stat().st_size:
                    data += "\n[stderr]\n" + stderr_path.read_bytes()[
                        -manager.stream_limit:].decode(errors="replace")
                yield f"data: {json.dumps({'stream': 'snapshot', 'data': data})}\n\n"
            yield f"data: {json.dumps({'stream': 'status', 'status': job.status, 'exit_code': job.exit_code, 'error': job.error})}\n\n"
            if job.status in ("completed", "failed", "stopped", "interrupted"):
                return
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=10)
                except asyncio.TimeoutError:
                    process = manager.processes.get(scan_id)
                    item = {
                        "stream": "heartbeat",
                        "status": "running",
                        "process_alive": bool(
                            process and process.returncode is None
                        ),
                    }
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("status") in ("completed", "failed", "stopped", "interrupted"):
                    break
        finally:
            manager.unsubscribe(scan_id, queue)
    return StreamingResponse(stream(), media_type="text/event-stream")

@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: int, db: Session = Depends(get_db)):
    need(db, ScanJob, scan_id)
    return {"stopped": await manager.stop(scan_id)}

@router.get("", response_model=list[ScanJobOut])
def jobs(target_id: int | None = None, db: Session = Depends(get_db)):
    statement = select(ScanJob).order_by(ScanJob.id.desc())
    if target_id:
        statement = statement.where(ScanJob.target_id == target_id)
    return db.scalars(statement.limit(200)).all()

@router.get("/{scan_id}", response_model=ScanJobOut)
def job(scan_id: int, db: Session = Depends(get_db)):
    return need(db, ScanJob, scan_id)

def _delete_scan_job(db: Session, job: ScanJob) -> None:
    for child in db.scalars(select(ScanJob).where(
            ScanJob.parent_scan_id == job.id)).all():
        _delete_scan_job(db, child)
    project = db.get(Project, job.project_id)
    target = db.get(Target, job.target_id)
    if project and target:
        shutil.rmtree(scan_directory(project, target, job.id), ignore_errors=True)
    db.execute(sa_delete(ScanArtifact).where(ScanArtifact.scan_job_id == job.id))
    db.execute(sa_delete(HostObservation).where(HostObservation.scan_job_id == job.id))
    db.execute(sa_delete(ServiceObservation).where(ServiceObservation.scan_job_id == job.id))
    db.delete(job)

@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    job = need(db, ScanJob, scan_id)
    if job.status in ("queued", "running"):
        raise HTTPException(409, "Stop the scan before deleting it")
    _delete_scan_job(db, job)
    db.commit()

@router.patch("/{scan_id}", response_model=ScanJobOut)
def update_job(scan_id: int, body: ScanJobUpdate, db: Session = Depends(get_db)):
    row = need(db, ScanJob, scan_id)
    row.alias = body.alias.strip()
    row.tags = json.dumps(body.tags, ensure_ascii=False)
    db.commit()
    db.refresh(row)
    return row

@router.post("/{scan_id}/rerun", response_model=ScanJobOut, status_code=201)
async def rerun(scan_id: int, db: Session = Depends(get_db)):
    previous = need(db, ScanJob, scan_id)
    target = need(db, Target, previous.target_id)
    if previous.source != "executed":
        raise HTTPException(409, "Imported scans cannot be rerun")
    argv = shlex.split(previous.command)
    known_binaries = ("nmap", "masscan")
    if (
        not argv
        or argv[-1] != target.ip
        or not (
            argv[0] in known_binaries
            or (len(argv) > 1 and argv[0] == "pkexec" and argv[1] in known_binaries)
        )
    ):
        raise HTTPException(409, "The stored command cannot be safely rerun")
    for flag in ("-oA", "-oX"):
        if flag in argv:
            index = argv.index(flag)
            if index + 1 >= len(argv):
                raise HTTPException(409, "The stored command is incomplete")
            del argv[index:index + 2]
    row = ScanJob(
        project_id=previous.project_id, target_id=previous.target_id,
        profile_id=previous.profile_id, source="executed", status="queued",
        command=shlex.join(argv), alias=previous.alias, tags=previous.tags,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    manager.enqueue(row.id, argv)
    return row

@router.get("/{scan_id}/artifacts", response_model=list[ScanArtifactOut])
def artifacts(scan_id: int, db: Session = Depends(get_db)):
    need(db, ScanJob, scan_id)
    return db.scalars(select(ScanArtifact).where(
        ScanArtifact.scan_job_id == scan_id)).all()

@router.get("/{scan_id}/artifacts/{artifact_id}/download")
def download_artifact(scan_id: int, artifact_id: int, db: Session = Depends(get_db)):
    need(db, ScanJob, scan_id)
    artifact = need(db, ScanArtifact, artifact_id)
    if artifact.scan_job_id != scan_id:
        raise HTTPException(404, "Not found")
    path = __import__("pathlib").Path(artifact.path)
    if not path.is_file():
        raise HTTPException(410, "Artifact file is no longer available")
    return FileResponse(path, filename=artifact.original_name or path.name,
                        media_type="application/octet-stream")

@router.get("/{scan_id}/observations", response_model=list[ObservationOut])
def observations(scan_id: int, db: Session = Depends(get_db)):
    need(db, ScanJob, scan_id)
    return db.scalars(select(ServiceObservation).where(
        ServiceObservation.scan_job_id == scan_id).order_by(
        ServiceObservation.port)).all()

@router.get("/{scan_id}/export")
def export_observations(scan_id: int, format: str = "json",
                        db: Session = Depends(get_db)):
    need(db, ScanJob, scan_id)
    rows = db.scalars(select(ServiceObservation).where(
        ServiceObservation.scan_job_id == scan_id).order_by(
        ServiceObservation.protocol, ServiceObservation.port)).all()
    fields = ("port", "protocol", "state", "name", "product", "version",
              "extra_info", "scripts", "cpe", "tls", "detection_evidence")
    data = [{field: getattr(row, field) for field in fields} for row in rows]
    if format == "json":
        return Response(json.dumps(data, ensure_ascii=False, indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="scan-{scan_id}.json"'})
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)
        return Response(output.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition":
                                 f'attachment; filename="scan-{scan_id}.csv"'})
    raise HTTPException(400, "Format must be json or csv")

@router.post("/import/{target_id}", response_model=ScanJobOut, status_code=201)
async def upload_xml(target_id: int, file: UploadFile = File(...),
                     db: Session = Depends(get_db)):
    target = need(db, Target, target_id)
    project = need(db, Project, target.project_id)
    try:
        content = await file.read(10 * 1024 * 1024 + 1)
        return import_xml(db, target, project, content,
                          file.filename or "nmap.xml")
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@router.get("/compare/{base_id}/{current_id}")
def compare(base_id: int, current_id: int, db: Session = Depends(get_db)):
    base, current = need(db, ScanJob, base_id), need(db, ScanJob, current_id)
    if base.target_id != current.target_id:
        raise HTTPException(400, "Scans must belong to the same target")
    return compare_jobs(db, base_id, current_id)

@router.get("/compare/{base_id}/{current_id}/export")
def export_compare(base_id: int, current_id: int,
                   db: Session = Depends(get_db)):
    base, current = need(db, ScanJob, base_id), need(db, ScanJob, current_id)
    if base.target_id != current.target_id:
        raise HTTPException(400, "Scans must belong to the same target")
    data = compare_jobs(db, base_id, current_id)
    return Response(json.dumps(data, ensure_ascii=False, indent=2),
                    media_type="application/json",
                    headers={"Content-Disposition":
                             f'attachment; filename="scan-{base_id}-to-{current_id}.json"'})
