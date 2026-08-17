from __future__ import annotations
import json
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...models import AutoReconRun, Execution, Project, ScanJob, Service, Target
from ..core.support import safe_part
from ..scan_center.service import capture_scan_evidence, ingest_xml


def run_output_dir(project: Project, run_id: int) -> Path:
    return WORKSPACE_DIR / "projects" / safe_part(project.name) / "autorecon" / str(run_id)


def render_autorecon_command(targets: list[Target], output_dir: Path) -> list[str]:
    # --disable-keyboard-control: without it AutoRecon tries to read live
    # keypresses from stdin and crashes with termios.error the moment it's
    # not attached to a real TTY (confirmed live -- this subprocess never is).
    # --ignore-plugin-checks: AutoRecon refuses to start at all if ANY
    # referenced tool is missing (e.g. oracle-scanner/tnscmd10g aren't
    # installed here); this degrades those specific plugins instead.
    # --only-scans-dir: skip exploit/loot/report scaffolding we don't use.
    # Never pass --single-target, even for one target, so the output layout
    # (<output_dir>/<ip>/scans/...) is identical for 1 or N targets --
    # confirmed live, this is what the importer below relies on.
    return ["autorecon", *(target.ip for target in targets),
            "--disable-keyboard-control", "--ignore-plugin-checks",
            "--only-scans-dir", "-o", str(output_dir)]


def import_autorecon_run(db: Session, run: AutoReconRun) -> int:
    """Walk a completed autorecon run's real output tree and turn it into
    the same Service/ServiceObservation/Execution/graph-node shapes a manual
    scan + per-command run would have produced. Reuses ingest_xml/
    capture_scan_evidence wholesale (Service upsert, positive-NSE Finding
    auto-capture) via a bookkeeping-only ScanJob per target, in the same
    order ScanManager._run already uses for a manual scan -- rather than
    re-deriving any of that logic here."""
    project = db.get(Project, run.project_id)
    target_ids = json.loads(run.target_ids or "[]")
    imported = 0
    for target_id in target_ids:
        target = db.get(Target, target_id)
        if not target:
            continue
        scans_dir = Path(run.output_dir) / target.ip / "scans"
        if not scans_dir.is_dir():
            continue
        job = ScanJob(project_id=project.id, target_id=target.id, source="autorecon",
                      status="completed", command=run.command)
        db.add(job)
        db.flush()
        xml_path = scans_dir / "xml" / "_full_tcp_nmap.xml"
        if xml_path.is_file() and xml_path.stat().st_size:
            ingest_xml(db, job, target, project, xml_path.read_bytes(), xml_path.name)
        capture_scan_evidence(db, job)
        for port_dir in sorted(scans_dir.glob("tcp*")):
            if not port_dir.is_dir():
                continue
            try:
                port = int(port_dir.name.removeprefix("tcp"))
            except ValueError:
                continue
            service = db.scalar(select(Service).where(
                Service.target_id == target.id, Service.port == port,
                Service.protocol == "tcp"))
            for result_file in sorted(port_dir.iterdir()):
                if result_file.is_dir() or result_file.suffix not in (".txt", ".html"):
                    continue
                # AutoRecon names files tcp_<port>_<service>_<plugin>.txt --
                # strip both prefixes so the label reads as just the plugin.
                slug = result_file.stem.removeprefix(f"tcp_{port}_")
                if service and slug.startswith(f"{service.name}_"):
                    slug = slug[len(service.name) + 1:]
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
