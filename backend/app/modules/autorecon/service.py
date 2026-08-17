from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path
from xml.etree.ElementTree import ParseError
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...models import AutoReconRun, Execution, Project, ScanArtifact, ScanJob, Service, Target
from ..core.support import safe_part
from ..scan_center.service import capture_scan_evidence, ingest_xml

# A plugin's output file can still be mid-write when a poll lands on it
# (feroxbuster in particular streams matches out over minutes) -- importing
# a half-written file would capture it forever, since import_autorecon_run
# is dedup'd by output_path and never revisits a path it's already seen.
# Skipping anything modified more recently than this just defers it to the
# next poll, once the plugin has actually finished with it.
_QUIET_PERIOD_SECONDS = 8


def run_output_dir(project: Project, run_id: int) -> Path:
    return WORKSPACE_DIR / "projects" / safe_part(project.name) / "autorecon" / str(run_id)


def render_autorecon_command(targets: list[Target], output_dir: Path,
                             extra_args: list[str] | None = None) -> list[str]:
    # --disable-keyboard-control: without it AutoRecon tries to read live
    # keypresses from stdin and crashes with termios.error the moment it's
    # not attached to a real TTY (confirmed live -- this subprocess never is).
    # --ignore-plugin-checks: AutoRecon refuses to start at all if ANY
    # referenced tool is missing (e.g. oracle-scanner/tnscmd10g aren't
    # installed here); this degrades those specific plugins instead.
    # Never pass --single-target, even for one target, so the output layout
    # (<output_dir>/<ip>/scans/...) is identical for 1 or N targets --
    # confirmed live, this is what the importer below relies on.
    extra_args = extra_args or []
    managed = {"-o", "--output", "-t", "--target-file", "--single-target"}
    if any(arg in managed or arg.startswith("--output=") for arg in extra_args):
        raise ValueError("Target and output layout are managed by OSCP Workspace")
    return ["autorecon", *(target.ip for target in targets),
            "--disable-keyboard-control", "--ignore-plugin-checks",
            *extra_args, "-o", str(output_dir)]


def _bookkeeping_scan_job(db: Session, project: Project, target: Target,
                          run: AutoReconRun) -> ScanJob:
    """One ScanJob per (run, target), reused across every poll of the same
    run -- run.command is unique per AutoReconRun (it embeds that run's own
    output_dir), so it doubles as a stable lookup key without a new column."""
    job = db.scalar(select(ScanJob).where(
        ScanJob.project_id == project.id, ScanJob.target_id == target.id,
        ScanJob.source == "autorecon", ScanJob.command == run.command))
    if job:
        return job
    job = ScanJob(project_id=project.id, target_id=target.id, source="autorecon",
                  status="completed", command=run.command)
    db.add(job)
    db.flush()
    return job


def _register_native_artifacts(db: Session, job: ScanJob, target_dir: Path) -> None:
    for path in (path for path in target_dir.rglob("*") if path.is_file()):
        relative = path.relative_to(target_dir)
        # Port plugin outputs already become service-owned Execution nodes;
        # their XML is already registered by ingest_xml. Everything else is
        # a target-level native AutoRecon artifact.
        if (len(relative.parts) > 1 and relative.parts[0] == "scans"
                and (relative.parts[1] == "xml"
                     or relative.parts[1].startswith(("tcp", "udp")))):
            continue
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if db.scalar(select(ScanArtifact.id).where(
                ScanArtifact.scan_job_id == job.id,
                ScanArtifact.path == str(path), ScanArtifact.sha256 == digest)):
            continue
        db.add(ScanArtifact(scan_job_id=job.id, kind="command_output",
                            path=str(path), sha256=digest, size=len(content),
                            original_name=path.name[:255]))


def import_autorecon_run(db: Session, run: AutoReconRun) -> int:
    """Walk an autorecon run's real output tree and turn whatever's landed
    so far into the same Service/ServiceObservation/Execution/graph-node
    shapes a manual scan + per-command run would have produced. Reuses
    ingest_xml/capture_scan_evidence wholesale (Service upsert, positive-NSE
    Finding auto-capture) via a bookkeeping ScanJob per target, in the same
    order ScanManager._run already uses for a manual scan -- rather than
    re-deriving any of that logic here.

    Safe to call repeatedly against the same still-running run (the
    AutoReconManager poll loop does, every few seconds): the bookkeeping
    ScanJob is reused rather than recreated, ingest_xml/capture_scan_evidence
    are already dedup'd internally (Service upsert by port, Finding dedup by
    an internal_notes marker), and each result file is only ever turned into
    one Execution (matched by output_path) no matter how many times this
    runs. Returns the number of *new* Executions created by this call, not a
    running total -- callers accumulate into run.imported_count themselves.
    """
    project = db.get(Project, run.project_id)
    target_ids = json.loads(run.target_ids or "[]")
    imported = 0
    now = time.time()
    for target_id in target_ids:
        target = db.get(Target, target_id)
        if not target:
            continue
        target_dir = Path(run.output_dir) / target.ip
        scans_dir = target_dir / "scans"
        if not scans_dir.is_dir():
            continue
        job = _bookkeeping_scan_job(db, project, target, run)
        xml_dir = scans_dir / "xml"
        aggregate_groups = [
            [xml_dir / "_full_tcp_nmap.xml", xml_dir / "_quick_tcp_nmap.xml"],
            [xml_dir / "_top_100_udp_nmap.xml", xml_dir / "_custom_ports_udp_nmap.xml"],
        ]
        for aggregate_xml in aggregate_groups:
            for xml_path in aggregate_xml:
                if (not xml_path.is_file() or not xml_path.stat().st_size
                        or now - xml_path.stat().st_mtime < _QUIET_PERIOD_SECONDS):
                    continue
                try:
                    ingest_xml(db, job, target, project,
                               xml_path.read_bytes(), xml_path.name)
                    break
                except (ValueError, ParseError):
                    continue
        for xml_path in sorted(scans_dir.glob("*p*/xml/*.xml")):
            if (not xml_path.stat().st_size
                    or now - xml_path.stat().st_mtime < _QUIET_PERIOD_SECONDS):
                continue
            try:
                ingest_xml(db, job, target, project,
                           xml_path.read_bytes(), xml_path.name)
            except (ValueError, ParseError):
                continue
        if run.status not in {"queued", "running"}:
            _register_native_artifacts(db, job, target_dir)
        capture_scan_evidence(db, job)
        for port_dir in sorted(scans_dir.glob("*p*")):
            protocol = port_dir.name[:3]
            if not port_dir.is_dir() or protocol not in {"tcp", "udp"}:
                continue
            try:
                port = int(port_dir.name[3:])
            except ValueError:
                continue
            service = db.scalar(select(Service).where(
                Service.target_id == target.id, Service.port == port,
                Service.protocol == protocol))
            for result_file in sorted(port_dir.iterdir()):
                if result_file.is_dir() or result_file.suffix not in (".txt", ".html"):
                    continue
                if now - result_file.stat().st_mtime < _QUIET_PERIOD_SECONDS:
                    continue
                # AutoRecon names files <protocol>_<port>_<service>_<plugin>.txt --
                # strip both prefixes so the label reads as just the plugin.
                slug = result_file.stem.removeprefix(f"{protocol}_{port}_")
                if service and slug.startswith(f"{service.name}_"):
                    slug = slug[len(service.name) + 1:]
                existing = db.scalar(select(Execution).where(
                    Execution.output_path == str(result_file)))
                if existing:
                    if service and existing.service_id is None:
                        existing.service_id = service.id
                        existing.template_id = f"autorecon-{slug}"[:100]
                        existing.command = f"(AutoRecon) {slug}"
                    continue
                try:
                    content = result_file.read_text(errors="replace")[:2_000_000]
                except OSError:
                    continue
                db.add(Execution(
                    target_id=target.id, service_id=service.id if service else None,
                    template_id=f"autorecon-{slug}"[:100],
                    command=f"(AutoRecon) {slug}", stdout=content, cwd=str(port_dir),
                    status="completed", exit_code=0, output_path=str(result_file)))
                imported += 1
        db.commit()
    return imported
