from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import STATE_DIR
from ...models import PassiveActivity, Project, ScanArtifact, ScanJob, Target
from ...nmap_parser import parse_nmap
from ..graph import service as graph_service
from ..scan_center.service import (
    apply_scan_hosts, capture_scan_evidence, ingest_xml, scan_directory,
)

INBOX = STATE_DIR / "passive-inbox"
ARCHIVE = STATE_DIR / "passive-archive"
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
PORT = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+(open(?:\|filtered)?|closed|filtered)\s+"
    r"([^\s]+)(?:\s+(.*))?$",
    re.IGNORECASE,
)
REPORT = re.compile(r"^Nmap scan report for (?:(.*?) \()?([^ ()]+)\)?$", re.IGNORECASE)
SECRET = re.compile(
    r"(?i)(?P<key>(?:password|passwd|pass|token|secret))=(?P<value>[^,]+)")


def parse_nmap_text(output: str, target_ip: str, activity_id: int,
                    confidence: int = 85) -> list[dict]:
    """Parse stable fields from Nmap's human-readable port table."""
    hostname = ""
    services = []
    clean = ANSI.sub("", output).replace("\r", "\n")
    for raw_line in clean.splitlines():
        line = raw_line.strip()
        report = REPORT.match(line)
        if report and report.group(2) == target_ip:
            hostname = (report.group(1) or "").strip()
            continue
        match = PORT.match(line)
        if not match:
            continue
        port = int(match.group(1))
        if port > 65535:
            continue
        state, name = match.group(3).lower(), match.group(4)
        services.append({
            "port": port,
            "protocol": match.group(2).lower(),
            "state": state,
            "name": name,
            "product": "",
            "version": "",
            "extra_info": match.group(5) or "",
            "scripts": [],
            "cpe": [],
            "tls": name.lower().startswith(("ssl/", "https")),
            "detection_evidence": {
                "source": "passive-terminal",
                "activity_id": activity_id,
                "parser": "nmap-text-v1",
                "confidence": confidence,
                "raw_line": line,
            },
        })
    return [{"ip": target_ip, "hostname": hostname, "os_guess": "",
             "services": services}]


def _literal_targets(argv: list[str]) -> list[str]:
    targets = []
    for value in argv[1:]:
        try:
            targets.append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return list(dict.fromkeys(targets))


def _redact_argv(argv: list[str]) -> list[str]:
    return [SECRET.sub(lambda match: f"{match.group('key')}=<redacted>", value)
            for value in argv]


def _declared_xml_path(argv: list[str], cwd: str) -> Path | None:
    path = None
    for index, value in enumerate(argv[1:], 1):
        if value in {"-oA", "-oX"} and index + 1 < len(argv):
            path = argv[index + 1] + (".xml" if value == "-oA" else "")
        elif value.startswith("-oA") and len(value) > 3:
            path = value[3:] + ".xml"
        elif value.startswith("-oX") and len(value) > 3:
            path = value[3:]
    if not path or path == "-":
        return None
    candidate = Path(path)
    if not candidate.is_absolute() and not Path(cwd).is_absolute():
        return None
    return candidate if candidate.is_absolute() else Path(cwd) / candidate


def _fresh_declared_xml(argv: list[str], metadata: dict) -> bytes | None:
    path = _declared_xml_path(argv, str(metadata.get("cwd") or ""))
    started = metadata.get("started_at")
    if path is None or not started:
        return None
    try:
        owner_uid = int(os.environ.get("OSCP_WORKSPACE_OWNER_UID", os.getuid()))
        start_time = _timestamp(started).timestamp()
        end_time = _timestamp(metadata.get("ended_at")).timestamp()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                    or not 0 < info.st_size <= 10 * 1024 * 1024
                    or info.st_mtime < start_time - 2
                    or info.st_mtime > min(end_time + 2, time.time() + 2)):
                return None
            with os.fdopen(fd, "rb", closefd=False) as source:
                return source.read(10 * 1024 * 1024 + 1)
        finally:
            os.close(fd)
    except (OSError, TypeError, ValueError):
        return None


def _resolve_target(db: Session, ip: str) -> tuple[Project, Target]:
    matches = list(db.scalars(select(Target).where(Target.ip == ip)))
    if len(matches) == 1:
        target = matches[0]
        return db.get(Project, target.project_id), target
    if len(matches) > 1:
        raise ValueError("target belongs to more than one project")
    projects = list(db.scalars(select(Project).order_by(Project.id)))
    if len(projects) != 1:
        raise ValueError("a new target requires exactly one project")
    project = projects[0]
    target = Target(project_id=project.id, name=ip, ip=ip)
    db.add(target)
    db.flush()
    return project, target


def _timestamp(value: object, fallback: datetime | None = None) -> datetime:
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return fallback or datetime.now(timezone.utc)


def ingest_file(db: Session, metadata_path: Path) -> PassiveActivity:
    metadata_path = metadata_path.resolve()
    if metadata_path.parent != INBOX.resolve():
        raise ValueError("activity metadata is outside the passive inbox")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    process_key = str(metadata["process_key"])[:160]
    existing = db.scalar(select(PassiveActivity).where(
        PassiveActivity.process_key == process_key))
    if existing:
        return existing
    output_path = (INBOX / Path(str(metadata["output_file"])).name).resolve()
    if output_path.parent != INBOX.resolve() or not output_path.is_file():
        raise ValueError("captured output is missing")
    output = output_path.read_bytes()
    if len(output) > 20 * 1024 * 1024:
        raise ValueError("captured output exceeds 20 MiB")
    argv = metadata.get("argv")
    if not isinstance(argv, list) or not argv or Path(str(argv[0])).name != "nmap":
        raise ValueError("activity is not an nmap execution")
    argv = [str(value) for value in argv]
    redacted_argv = _redact_argv(argv)
    declared_xml = _fresh_declared_xml(argv, metadata)
    selected_output = declared_xml if declared_xml is not None else output
    capture_partial = bool(metadata.get("capture_truncated")) or bool(
        int(metadata.get("loss_count", 0)))
    confidence = 60 if capture_partial else 85
    xml_output = selected_output.lstrip().startswith((b"<?xml", b"<nmaprun")) or (
        "-oX" in argv and argv.index("-oX") + 1 < len(argv)
        and argv[argv.index("-oX") + 1] == "-")
    activity = PassiveActivity(
        process_key=process_key,
        tool="nmap",
        command=shlex.join(redacted_argv),
        argv=json.dumps(redacted_argv),
        cwd=str(metadata.get("cwd", "")),
        tty=str(metadata.get("tty", ""))[:160],
        pid=int(metadata["pid"]),
        ppid=int(metadata["ppid"]) if metadata.get("ppid") is not None else None,
        uid=int(metadata["uid"]),
        started_at=_timestamp(metadata.get("started_at")),
        ended_at=_timestamp(metadata.get("ended_at")),
        exit_code=int(metadata["exit_code"]) if metadata.get("exit_code") is not None else None,
        output_path=str(output_path),
        sha256=hashlib.sha256(selected_output).hexdigest(),
        parser="nmap-xml-v1" if xml_output else "nmap-text-v1",
        confidence=confidence,
        error="collector reported truncation or event loss" if capture_partial else "",
    )
    db.add(activity)
    db.flush()
    targets = _literal_targets(argv)
    if len(targets) != 1:
        activity.status = "unresolved"
        activity.error = "passive MVP requires exactly one literal IP target"
        db.commit()
        return activity
    try:
        project, target = _resolve_target(db, targets[0])
        if xml_output:
            try:
                hosts = parse_nmap(selected_output)
            except (ParseError, DefusedXmlException) as exc:
                raise ValueError("invalid Nmap XML output") from exc
            host = next((item for item in hosts if item["ip"] == target.ip), None)
        else:
            hosts = parse_nmap_text(output.decode("utf-8", errors="replace"), target.ip,
                                    activity.id, confidence)
            host = hosts[0]
        if host is None or not host["services"]:
            raise ValueError("no Nmap port-table observations found")
        job = ScanJob(
            project_id=project.id, target_id=target.id, source="passive",
            status="completed", command=activity.command,
            started_at=activity.started_at, ended_at=activity.ended_at,
            exit_code=activity.exit_code,
        )
        db.add(job)
        db.flush()
        if xml_output:
            ingest_xml(db, job, target, project, selected_output, "passive-output.xml")
            destination = scan_directory(project, target, job.id) / "nmap.xml"
            os.chmod(destination, 0o600)
            if declared_xml is not None and output:
                normal_path = destination.parent / "passive-stdout.txt"
                normal_path.write_bytes(output)
                os.chmod(normal_path, 0o600)
                db.add(ScanArtifact(
                    scan_job_id=job.id, kind="normal", path=str(normal_path),
                    sha256=hashlib.sha256(output).hexdigest(), size=len(output),
                    original_name="passive-stdout.txt",
                ))
        else:
            destination = scan_directory(project, target, job.id) / "passive-output.txt"
            destination.write_bytes(output)
            os.chmod(destination, 0o600)
            db.add(ScanArtifact(
                scan_job_id=job.id, kind="normal", path=str(destination),
                sha256=activity.sha256, size=len(output), original_name="passive-output.txt",
            ))
            apply_scan_hosts(db, job, target, hosts)
        activity.project_id = project.id
        activity.target_id = target.id
        activity.scan_job_id = job.id
        activity.output_path = str(destination)
        activity.status = "observed"
        activity.confidence = confidence
        db.flush()  # SessionLocal disables autoflush; include both XML and stdout artifacts.
        capture_scan_evidence(db, job)
        graph_service.sync_from_project(db, project.id)
        graph_service.record_snapshot(db, project.id)
        db.commit()
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        return activity
    except ValueError as exc:
        db.rollback()
        persisted = db.scalar(select(PassiveActivity).where(
            PassiveActivity.process_key == process_key))
        if persisted is None:
            activity.project_id = activity.target_id = activity.scan_job_id = None
            activity.status = "unresolved"
            activity.error = str(exc)
            db.add(activity)
        else:
            activity = persisted
            activity.status = "unresolved"
            activity.error = str(exc)
        db.commit()
        return activity


def sync_inbox(db: Session) -> dict[str, int]:
    INBOX.mkdir(parents=True, exist_ok=True)
    ARCHIVE.mkdir(parents=True, exist_ok=True)
    os.chmod(INBOX, 0o700)
    os.chmod(ARCHIVE, 0o700)
    result = {"processed": 0, "failed": 0}
    for metadata_path in sorted(INBOX.glob("*.json")):
        try:
            ingest_file(db, metadata_path)
            metadata_path.replace(ARCHIVE / metadata_path.name)
            result["processed"] += 1
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            db.rollback()
            result["failed"] += 1
    return result
