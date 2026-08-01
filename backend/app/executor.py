import asyncio, json, os, shlex, signal
from pathlib import Path
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Execution, Service, Target
from .nmap_parser import parse_nmap
from .time import utcnow

processes: dict[int, asyncio.subprocess.Process] = {}
queues: dict[int, asyncio.Queue] = {}


def classify_execution_status(
    exit_code: int,
    argv: list[str],
    stdout: str,
    stderr: str,
) -> str:
    if exit_code != 0:
        return "failed"
    if Path(argv[0]).name == "nmap":
        output = f"{stdout}\n{stderr}".lower()
        if "0 hosts up" in output or "host seems down" in output:
            return "no_response"
    return "completed"


def require_observation(status: str, argv: list[str], observed: bool) -> str:
    if status == "completed" and "-oX" in argv and not observed:
        return "no_response"
    return status


def reconcile_completed_observations(db: Session) -> int:
    changed = 0
    rows = db.query(Execution).filter(Execution.status == "completed").all()
    for row in rows:
        try:
            argv = shlex.split(row.command)
            if "-oX" not in argv:
                continue
            xml_path = Path(argv[argv.index("-oX") + 1])
            if not xml_path.is_file():
                continue
            observed = update_execution_observations(
                db, row, xml_path.read_bytes(),
            )
            corrected = require_observation(row.status, argv, observed)
            if corrected != row.status:
                row.status = corrected
                changed += 1
        except (OSError, ValueError):
            continue
    if changed:
        db.commit()
    return changed


def update_execution_observations(
    db: Session,
    execution: Execution,
    xml_content: bytes,
) -> bool:
    try:
        hosts = parse_nmap(xml_content)
    except Exception:
        return False
    target = db.get(Target, execution.target_id)
    host = next(
        (item for item in hosts if target and item["ip"] == target.ip),
        hosts[0] if hosts else None,
    )
    updated = False
    if target and host:
        if host["hostname"]:
            target.hostname = host["hostname"]
            updated = True
        if host["os_guess"]:
            target.os_guess = host["os_guess"]
            updated = True
        if updated:
            target.updated_at = utcnow()
    if not execution.service_id or not host:
        return updated
    service = db.get(Service, execution.service_id)
    if not service:
        return updated
    observation = next(
        (
            item for item in host["services"]
            if item["port"] == service.port
            and item["protocol"] == service.protocol
        ),
        None,
    )
    if not observation:
        return updated
    for field in ("product", "version", "extra_info"):
        if observation[field]:
            setattr(service, field, observation[field])
            updated = True
    service.cpe = json.dumps(observation.get("cpe", []), ensure_ascii=False)
    service.tls = bool(observation.get("tls", False))
    service.detection_evidence = json.dumps(
        observation.get("detection_evidence", {}), ensure_ascii=False)
    updated = True
    return updated


def update_service_identity(
    db: Session,
    execution: Execution,
    xml_content: bytes,
) -> bool:
    """Backward-compatible name for callers and tests."""
    return update_execution_observations(db, execution, xml_content)


async def run_execution(execution_id: int, argv: list[str], cwd: Path, output_file: Path):
    queue = queues.setdefault(execution_id, asyncio.Queue())
    chunks = {"stdout": [], "stderr": []}
    try:
        with SessionLocal() as db:
            row = db.get(Execution, execution_id)
            if row:
                row.status = "running"; row.output_path = str(output_file); db.commit()
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True)
        processes[execution_id] = process
        async def pump(stream, kind):
            while line := await stream.readline():
                text = line.decode(errors="replace")
                chunks[kind].append(text)
                await queue.put({"stream": kind, "data": text})
        await asyncio.gather(pump(process.stdout, "stdout"), pump(process.stderr, "stderr"))
        code = await process.wait()
        output_file.write_text("".join(chunks["stdout"])+
                               "".join(chunks["stderr"]), encoding="utf-8")
        with SessionLocal() as db:
            row = db.get(Execution, execution_id)
            if row:
                row.stdout = "".join(chunks["stdout"]); row.stderr = "".join(chunks["stderr"])
                row.exit_code = code; row.ended_at = utcnow()
                row.status = (
                    "stopped" if row.stopped else classify_execution_status(
                        code, argv, row.stdout, row.stderr,
                    )
                )
                observed = False
                if code == 0 and "-oX" in argv:
                    xml_path = Path(argv[argv.index("-oX") + 1])
                    if xml_path.is_file():
                        observed = update_execution_observations(
                            db, row, xml_path.read_bytes(),
                        )
                row.status = require_observation(row.status, argv, observed)
                from .modules.service_intelligence.router import sync_execution_to_runbooks
                sync_execution_to_runbooks(db, row)
                db.commit(); status = row.status
        await queue.put({"stream": "status", "status": status, "exit_code": code})
    except Exception as exc:
        with SessionLocal() as db:
            row = db.get(Execution, execution_id)
            if row:
                row.status = "failed"; row.error = str(exc); row.ended_at = utcnow(); db.commit()
        await queue.put({"stream": "status", "status": "failed", "error": str(exc)})
    finally:
        processes.pop(execution_id, None)

async def stop_execution(execution_id: int):
    process = processes.get(execution_id)
    if not process or process.returncode is not None:
        return False
    os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(process.wait(), timeout=3)
    except asyncio.TimeoutError:
        os.killpg(process.pid, signal.SIGKILL)
    with SessionLocal() as db:
        row = db.get(Execution, execution_id)
        if row:
            row.stopped = True; row.status = "stopped"; row.ended_at = utcnow(); db.commit()
    return True


async def shutdown_executions():
    for execution_id in list(processes):
        await stop_execution(execution_id)
