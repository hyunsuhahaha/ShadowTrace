import asyncio, os, signal
from pathlib import Path
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Execution
from .time import utcnow

processes: dict[int, asyncio.subprocess.Process] = {}
queues: dict[int, asyncio.Queue] = {}

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
                row.status = "stopped" if row.stopped else ("completed" if code == 0 else "failed")
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
