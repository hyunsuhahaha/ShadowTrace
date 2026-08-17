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
    Evidence, Finding, FindingAsset, FindingEvidence, HostObservation,
    Project, ScanArtifact, ScanJob, ScanProfile, Service, ServiceObservation, Target,
)
from ...nmap_parser import parse_nmap
from ...time import utcnow

BUILTIN_PROFILES = [
    ("Top TCP services", "quick", "Fast version detection on the selected number of top TCP ports",
     "-Pn -sT --top-ports {top_ports} -sV --version-light -T4", "nmap", ""),
    ("Fast full TCP discovery", "full_tcp", "All TCP ports at a practical minimum rate",
     "-Pn -sT -p- --min-rate 1000 -T4", "nmap", "selected_syn_detail"),
    ("Fast full TCP SYN discovery", "full_tcp_syn",
     "Privileged SYN scan across all TCP ports",
     "-Pn -p- --min-rate 1000 -T4", "nmap", "selected_syn_detail"),
    ("Balanced full TCP discovery", "full_tcp_balanced",
     "All TCP ports with adaptive default timing", "-Pn -sT -p- -T3", "nmap",
     "selected_syn_detail"),
    ("Selected ports version scan", "selected_version",
     "Version detection on selected TCP ports", "-Pn -sT -sV -p{ports} -T3", "nmap", ""),
    ("Selected ports detail", "selected_ports",
     "Default scripts and version detection on selected TCP ports",
     "-Pn -sT -sC -sV -p{ports} -T3", "nmap", ""),
    ("Selected ports SYN detail", "selected_syn_detail",
     "Privileged SYN scan with default scripts and version detection",
     "-Pn -sC -sV -p{ports} -T3", "nmap", ""),
    ("Selected ports deep version scan", "selected_deep",
     "All version probes on selected TCP ports",
     "-Pn -sT -sC -sV --version-all -p{ports} -T3", "nmap", ""),
    ("Top UDP services", "udp_top",
     "Selected number of top UDP ports with light version detection; privilege required",
     "-Pn -sU --top-ports {top_ports} -sV --version-light -T3", "nmap", ""),
    ("Full UDP discovery", "udp_full",
     "All UDP ports; privilege required and potentially extremely slow",
     "-Pn -sU -p- -T3", "nmap", ""),
    ("Selected UDP ports", "selected_udp",
     "Version detection on selected UDP ports; privilege required",
     "-Pn -sU -sV -p{ports} -T3", "nmap", ""),
    ("Fast port discovery (masscan)", "masscan_discovery",
     "Full TCP port sweep with masscan; review the open ports and run a detail "
     "scan on them yourself",
     "-p1-65535 --rate 5000 --open", "masscan", ""),
    ("Fast discovery + auto detail scan", "masscan_auto_chain",
     "Full TCP port sweep with masscan; automatically queues an Nmap -sC -sV "
     "scan on whatever ports it finds",
     "-p1-65535 --rate 5000 --open", "masscan", "selected_syn_detail"),
]
SAFE_EXTRA = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_.:-]*(?:=[A-Za-z0-9_.,:/-]+)?$")
SAFE_PORTS = re.compile(r"^\d+(?:[-,]\d+)*$")
PRIVILEGED_KINDS = {
    "full_tcp_syn", "selected_syn_detail", "udp_top", "udp_full",
    "selected_udp", "masscan_discovery", "masscan_auto_chain",
}

POSITIVE_SCRIPT_MARKERS = (
    "vulnerable", "anonymous ftp login allowed", "anonymous login allowed",
    "valid credentials", "empty password", "authentication disabled",
    "open proxy", "recursion enabled",
)
NEGATIVE_SCRIPT_MARKERS = (
    "not vulnerable", "couldn't find", "could not find", "no valid",
    "login failed", "authentication required", "recursion disabled",
)
SECURITY_SCRIPT_IDS = {
    "ftp-anon", "http-default-accounts", "http-open-proxy",
    "mysql-empty-password", "ms-sql-empty-password", "dns-recursion",
}

def seed_profiles(db: Session) -> None:
    for name, kind, description, arguments, engine, chain_kind in BUILTIN_PROFILES:
        profile = db.scalar(select(ScanProfile).where(ScanProfile.kind == kind))
        if profile and profile.builtin:
            profile.name = name
            profile.description = description
            profile.arguments = arguments
            profile.engine = engine
            profile.chain_kind = chain_kind
        elif not profile:
            db.add(ScanProfile(name=name, kind=kind, description=description,
                               arguments=arguments, engine=engine,
                               chain_kind=chain_kind, builtin=True))
    db.commit()

def render_scan(profile: ScanProfile, target: Target, ports: str = "",
                extra_arguments: list[str] | None = None,
                top_ports: int = 100,
                command_override: str | None = None) -> tuple[str, list[str]]:
    args = profile.arguments
    if "{ports}" in args:
        if not ports or not SAFE_PORTS.fullmatch(ports):
            raise ValueError("Selected ports must contain only numbers, commas, and ranges")
        args = args.replace("{ports}", ports)
    if "{top_ports}" in args:
        if not 1 <= top_ports <= 65535:
            raise ValueError("Top ports must be between 1 and 65535")
        args = args.replace("{top_ports}", str(top_ports))
    extras = extra_arguments or []
    if any(not SAFE_EXTRA.fullmatch(value) for value in extras):
        raise ValueError("An additional Nmap argument is not allowed")
    binary = profile.engine or "nmap"
    privileged = profile.kind in PRIVILEGED_KINDS
    prefix = ["pkexec", binary] if privileged else [binary]
    argv = [*prefix, *shlex.split(args), *extras, target.ip]
    display_argv = (
        ["sudo", binary, *shlex.split(args), *extras, target.ip]
        if privileged
        else argv
    )
    if command_override is not None:
        try:
            edited = shlex.split(command_override)
        except ValueError as exc:
            raise ValueError(f"The edited command is incomplete: {exc}") from exc
        if edited[:1] == ["sudo"]:
            edited = edited[1:]
        expected_binary = profile.engine or "nmap"
        if not edited or edited[0] != expected_binary:
            raise ValueError(f"This profile must execute {expected_binary}")
        if edited.count(target.ip) != 1 or edited[-1] != target.ip:
            raise ValueError("The edited command must end with the selected target IP")
        if any(flag in edited for flag in ("-oA", "-oX")):
            raise ValueError("Output paths are managed by Scan Center")
        argv = ["pkexec", *edited] if privileged else edited
        display_argv = ["sudo", *edited] if privileged else edited
    return shlex.join(display_argv), argv

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
        cpe = json.dumps(item.get("cpe", []), ensure_ascii=False)
        detection_evidence = json.dumps(
            item.get("detection_evidence", {}), ensure_ascii=False)
        values = {**item, "scripts": scripts, "cpe": cpe,
                  "detection_evidence": detection_evidence}
        db.add(ServiceObservation(
            scan_job_id=job.id, target_id=target.id,
            **values,
        ))
        current = db.scalar(select(Service).where(
            Service.target_id == target.id, Service.port == item["port"],
            Service.protocol == item["protocol"]))
        if current:
            for key, value in values.items():
                if key in {"product", "version", "extra_info"} and not value:
                    continue
                if key == "cpe" and value == "[]":
                    continue
                setattr(current, key, value)
        elif item["state"] == "open":
            # Nmap emits a <port> element for every scanned port, not just
            # ones that answered — a targeted scan (-p 80,443) against a
            # port nothing is listening on still shows up here as
            # state="closed"/"filtered". ServiceObservation keeps every
            # state for scan-history/diffing, but Service drives the
            # Service Enumeration list, so a never-open port has no
            # business creating a row a user would read as "found this".
            db.add(Service(target_id=target.id, **values))
    target.hostname = host["hostname"] or target.hostname
    target.os_guess = host["os_guess"] or target.os_guess
    target.updated_at = utcnow()
    db.flush()


def _security_signal(script_id: str, output: str) -> bool:
    script_id, text = script_id.lower(), output.lower()
    if any(marker in text for marker in NEGATIVE_SCRIPT_MARKERS):
        return False
    relevant = (
        script_id in SECURITY_SCRIPT_IDS
        or "vuln" in script_id
        or script_id.endswith("-brute")
    )
    return relevant and any(marker in text for marker in POSITIVE_SCRIPT_MARKERS)


def _signal_severity(script_id: str, output: str) -> str:
    text = f"{script_id} {output}".lower()
    if any(value in text for value in ("critical", "ms17-010", "heartbleed")):
        return "Critical"
    if any(value in text for value in ("vulnerable", "valid credentials")):
        return "High"
    return "Medium"


def capture_scan_evidence(db: Session, job: ScanJob) -> dict[str, int]:
    """Register immutable scan artifacts and positive NSE results for review."""
    target = db.get(Target, job.target_id)
    artifacts = db.scalars(select(ScanArtifact).where(
        ScanArtifact.scan_job_id == job.id)).all()
    created_evidence = 0
    for artifact in artifacts:
        existing = db.scalar(select(Evidence).where(
            Evidence.source_type == "scan", Evidence.source_id == job.id,
            Evidence.file_path == artifact.path))
        if existing:
            continue
        kind = "nmap" if artifact.kind in {"xml", "normal", "grepable"} else "command_output"
        db.add(Evidence(
            project_id=job.project_id, target_id=job.target_id,
            title=f"Nmap scan #{job.id} · {artifact.kind}",
            description=f"Automatically captured from: {job.command}",
            kind=kind, source_type="scan", source_id=job.id,
            file_path=artifact.path, original_name=artifact.original_name,
            sha256=artifact.sha256, size=artifact.size,
            hostname=target.hostname or target.ip, include_report=False,
            tags=json.dumps(["auto-captured", "nmap", artifact.kind]),
        ))
        created_evidence += 1
    db.flush()

    created_findings = 0
    observations = db.scalars(select(ServiceObservation).where(
        ServiceObservation.scan_job_id == job.id)).all()
    for observation in observations:
        service = db.scalar(select(Service).where(
            Service.target_id == job.target_id,
            Service.port == observation.port,
            Service.protocol == observation.protocol))
        for script in json.loads(observation.scripts or "[]"):
            script_id, output = script.get("id", ""), script.get("output", "")
            if not _security_signal(script_id, output):
                continue
            marker = f"scan:{job.id}:{observation.protocol}:{observation.port}:{script_id}"
            if db.scalar(select(Finding.id).where(Finding.internal_notes == marker)):
                continue
            title = f"{script_id.replace('-', ' ').title()} on {target.ip}:{observation.port}"
            excerpt = Evidence(
                project_id=job.project_id, target_id=job.target_id,
                service_id=service.id if service else None, title=title,
                description="Positive Nmap NSE result captured automatically.",
                kind="nmap", source_type="scan", source_id=job.id,
                hostname=target.hostname or target.ip, include_report=False,
                markdown=f"```text\n$ {job.command}\n\n[{script_id}]\n{output}\n```",
                tags=json.dumps(["auto-captured", "nmap", "finding-candidate"]),
            )
            db.add(excerpt); db.flush()
            severity = _signal_severity(script_id, output)
            finding = Finding(
                project_id=job.project_id, target_id=job.target_id,
                service_id=service.id if service else None, title=title,
                category="Automated scan candidate", severity=severity,
                final_risk=severity, status="Needs Review",
                summary=f"Nmap reported a positive {script_id} result.",
                description=output, reproduction_steps=f"Run:\n\n`{job.command}`",
                recommendation="Validate the result manually, document impact, and apply the relevant vendor remediation.",
                tags=json.dumps(["automated", "nmap", script_id]),
                internal_notes=marker, disclosure="INTERNAL",
            )
            db.add(finding); db.flush()
            db.add(FindingEvidence(
                finding_id=finding.id, evidence_id=excerpt.id,
                caption=f"Nmap {script_id} output", include_internal=True,
                include_client=False, is_primary=True,
            ))
            db.add(FindingAsset(
                finding_id=finding.id, target_id=job.target_id,
                service_id=service.id if service else None,
            ))
            created_evidence += 1
            created_findings += 1
    db.flush()
    return {"evidence_count": created_evidence, "finding_count": created_findings}


def create_chain_job(db: Session, job: ScanJob) -> tuple[int, list[str]] | None:
    """If the completed job's profile requests an automatic follow-up scan
    (masscan discovery -> Nmap detail), queue it against the ports found and
    return its (job id, argv) for the caller to enqueue."""
    if not job.profile_id:
        return None
    profile = db.get(ScanProfile, job.profile_id)
    if not profile or not profile.chain_kind:
        return None
    ports = sorted({row for row in db.scalars(select(ServiceObservation.port).where(
        ServiceObservation.scan_job_id == job.id,
        ServiceObservation.protocol == "tcp",
        ServiceObservation.state == "open"))})
    if not ports:
        return None
    chain_profile = db.scalar(select(ScanProfile).where(
        ScanProfile.kind == profile.chain_kind))
    if not chain_profile:
        return None
    target = db.get(Target, job.target_id)
    ports_csv = ",".join(str(port) for port in ports)
    try:
        command, argv = render_scan(chain_profile, target, ports=ports_csv)
    except ValueError:
        return None
    chain_job = ScanJob(project_id=job.project_id, target_id=job.target_id,
                        profile_id=chain_profile.id, parent_scan_id=job.id,
                        source="executed", status="queued", command=command)
    db.add(chain_job)
    db.flush()
    return chain_job.id, argv


def import_xml(db: Session, target: Target, project: Project, content: bytes,
               original_name: str) -> ScanJob:
    job = ScanJob(project_id=project.id, target_id=target.id, source="import",
                  status="processing", command=f"Imported {original_name}")
    db.add(job); db.flush()
    ingest_xml(db, job, target, project, content, original_name)
    job.status = "completed"; job.ended_at = utcnow(); job.exit_code = 0
    capture_scan_evidence(db, job)
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
                "extra_info": row.extra_info, "cpe": row.cpe, "tls": row.tls,
                "detection_evidence": row.detection_evidence}
    for key in sorted(current.keys() - base.keys()):
        added.append(public(current[key]))
    for key in sorted(base.keys() - current.keys()):
        removed.append(public(base[key]))
    fields = ("state", "name", "product", "version", "extra_info", "scripts",
              "cpe", "tls", "detection_evidence")
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
