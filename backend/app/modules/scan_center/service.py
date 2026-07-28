from __future__ import annotations
import hashlib
import json
import re
import shlex
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...models import (
    HostObservation, Project, ScanArtifact, ScanJob, ScanProfile,
    Service, ServiceObservation, Target,
)
from ...nmap_parser import parse_nmap
from ...time import utcnow

BUILTIN_PROFILES = [
    ("Quick service scan", "quick", "Common ports with default scripts and version detection", "-Pn -sC -sV"),
    ("Full TCP scan", "full_tcp", "All TCP ports with an OSCP-friendly rate", "-Pn -p- --min-rate 3000 -T4"),
    ("Selected ports detail", "selected_ports", "Default scripts and versions on selected ports", "-Pn -sC -sV -p{ports}"),
]
SAFE_EXTRA = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_.:-]*(?:=[A-Za-z0-9_.,:/-]+)?$")
SAFE_PORTS = re.compile(r"^\d+(?:[-,]\d+)*$")

def seed_profiles(db: Session) -> None:
    for name, kind, description, arguments in BUILTIN_PROFILES:
        if not db.scalar(select(ScanProfile).where(ScanProfile.kind == kind)):
            db.add(ScanProfile(name=name, kind=kind, description=description,
                               arguments=arguments, builtin=True))
    db.commit()

def render_scan(profile: ScanProfile, target: Target, ports: str = "",
                extra_arguments: list[str] | None = None) -> tuple[str, list[str]]:
    args = profile.arguments
    if "{ports}" in args:
        if not ports or not SAFE_PORTS.fullmatch(ports):
            raise ValueError("Selected ports must contain only numbers, commas, and ranges")
        args = args.replace("{ports}", ports)
    extras = extra_arguments or []
    if any(not SAFE_EXTRA.fullmatch(value) for value in extras):
        raise ValueError("An additional Nmap argument is not allowed")
    argv = ["nmap", *shlex.split(args), *extras, target.ip]
    return shlex.join(argv), argv

def _safe(value: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in value).strip("._")
    if not cleaned:
        raise ValueError("Unsafe path component")
    return cleaned[:120]

def scan_directory(project: Project, target: Target, scan_id: int) -> Path:
    path = (WORKSPACE_DIR / "projects" / _safe(project.name) / "targets" /
            _safe(target.ip) / "scans" / str(scan_id))
    path.mkdir(parents=True, exist_ok=True)
    return path

def ingest_xml(db: Session, job: ScanJob, target: Target, project: Project,
               content: bytes, original_name: str) -> None:
    hosts = parse_nmap(content)
    host = next((item for item in hosts if item["ip"] == target.ip),
                hosts[0] if hosts else None)
    if not host:
        raise ValueError("No host found in Nmap XML")
    folder = scan_directory(project, target, job.id)
    xml_path = folder / "nmap.xml"
    xml_path.write_bytes(content)
    db.add(ScanArtifact(
        scan_job_id=job.id, kind="xml", path=str(xml_path),
        sha256=hashlib.sha256(content).hexdigest(), size=len(content),
        original_name=Path(original_name).name[:255],
    ))
    db.add(HostObservation(scan_job_id=job.id, target_id=target.id,
                           ip=host["ip"], hostname=host["hostname"],
                           os_guess=host["os_guess"]))
    for item in host["services"]:
        scripts = json.dumps(item["scripts"], ensure_ascii=False)
        db.add(ServiceObservation(
            scan_job_id=job.id, target_id=target.id,
            **{**item, "scripts": scripts},
        ))
        current = db.scalar(select(Service).where(
            Service.target_id == target.id, Service.port == item["port"],
            Service.protocol == item["protocol"]))
        values = {**item, "scripts": scripts}
        if current:
            for key, value in values.items():
                setattr(current, key, value)
        else:
            db.add(Service(target_id=target.id, **values))
    target.hostname = host["hostname"] or target.hostname
    target.os_guess = host["os_guess"] or target.os_guess
    target.updated_at = utcnow()
    db.flush()

def import_xml(db: Session, target: Target, project: Project, content: bytes,
               original_name: str) -> ScanJob:
    job = ScanJob(project_id=project.id, target_id=target.id, source="import",
                  status="processing", command=f"Imported {original_name}")
    db.add(job); db.flush()
    ingest_xml(db, job, target, project, content, original_name)
    job.status = "completed"; job.ended_at = utcnow(); job.exit_code = 0
    db.commit(); db.refresh(job)
    return job

def compare_jobs(db: Session, base_id: int, current_id: int) -> dict:
    def values(scan_id: int):
        rows = db.scalars(select(ServiceObservation).where(
            ServiceObservation.scan_job_id == scan_id)).all()
        return {(row.protocol, row.port): row for row in rows}
    base, current = values(base_id), values(current_id)
    added, removed, changed, unchanged = [], [], [], 0
    def public(row):
        return {"protocol": row.protocol, "port": row.port, "state": row.state,
                "name": row.name, "product": row.product, "version": row.version,
                "extra_info": row.extra_info}
    for key in sorted(current.keys() - base.keys()):
        added.append(public(current[key]))
    for key in sorted(base.keys() - current.keys()):
        removed.append(public(base[key]))
    fields = ("state", "name", "product", "version", "extra_info", "scripts")
    for key in sorted(base.keys() & current.keys()):
        changes = {field: {"before": getattr(base[key], field),
                           "after": getattr(current[key], field)}
                   for field in fields if getattr(base[key], field) != getattr(current[key], field)}
        if changes:
            changed.append({"protocol": key[0], "port": key[1], "changes": changes})
        else:
            unchanged += 1
    return {"base_scan_id": base_id, "current_scan_id": current_id,
            "added": added, "removed": removed, "changed": changed,
            "unchanged_count": unchanged}
