from __future__ import annotations
import asyncio
import hashlib
import json
import os
import signal
import shlex
from pathlib import Path
from ...database import SessionLocal
from ...models import Project, ScanArtifact, ScanJob, Target
from .service import ingest_xml, scan_directory
from ...time import utcnow

class ScanManager:
    def __init__(self, concurrency: int = 2, stream_limit: int = 2_000_000):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.stream_limit = stream_limit
        self.processes: dict[int, asyncio.subprocess.Process] = {}
        self.events: dict[int, set[asyncio.Queue]] = {}
        self.tasks: dict[int, asyncio.Task] = {}

    def enqueue(self, scan_id: int, argv: list[str]) -> None:
        self.events.setdefault(scan_id, set())
        task = asyncio.create_task(self._run(scan_id, argv))
        self.tasks[scan_id] = task
        task.add_done_callback(lambda _: self.tasks.pop(scan_id, None))

    def set_concurrency(self, concurrency: int) -> None:
        if self.processes or any(not task.done() for task in self.tasks.values()):
            raise RuntimeError("Concurrency cannot change while scans are active")
        self.semaphore = asyncio.Semaphore(concurrency)

    async def _publish(self, scan_id: int, event: dict) -> None:
        for queue in tuple(self.events.get(scan_id, set())):
            await queue.put(event)

    def subscribe(self, scan_id: int) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self.events.setdefault(scan_id, set()).add(queue)
        return queue

    def unsubscribe(self, scan_id: int, queue: asyncio.Queue) -> None:
        subscribers = self.events.get(scan_id)
        if subscribers:
            subscribers.discard(queue)

    async def _run(self, scan_id: int, argv: list[str]) -> None:
        async with self.semaphore:
            with SessionLocal() as db:
                job = db.get(ScanJob, scan_id)
                if not job or job.status == "stopped":
                    return
                target, project = db.get(Target, job.target_id), db.get(Project, job.project_id)
                folder = scan_directory(project, target, scan_id)
                output_base = folder / "nmap"
                final_argv = [*argv[:-1], "-oA", str(output_base), argv[-1]]
                job.command = shlex.join(final_argv); job.status = "running"
                job.started_at = utcnow(); db.commit()
            await self._publish(scan_id, {"stream": "status", "status": "running"})
            stdout_path = folder / "stdout.txt"
            stderr_path = folder / "stderr.txt"
            streamed = 0
            stream_notice_sent = False
            try:
                process = await asyncio.create_subprocess_exec(
                    *final_argv, cwd=folder, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, start_new_session=True)
                self.processes[scan_id] = process
                async def pump(stream, path: Path, kind: str):
                    nonlocal streamed, stream_notice_sent
                    with path.open("wb") as output:
                        while line := await stream.readline():
                            output.write(line); output.flush()
                            if streamed < self.stream_limit:
                                streamed += len(line)
                                await self._publish(scan_id, {
                                    "stream": kind, "data": line.decode(errors="replace")})
                            elif not stream_notice_sent:
                                stream_notice_sent = True
                                await self._publish(scan_id, {"stream": "stdout",
                                    "data": "\n[live output limit reached; full output remains in the artifact file]\n"})
                await asyncio.gather(
                    pump(process.stdout, stdout_path, "stdout"),
                    pump(process.stderr, stderr_path, "stderr"))
                code = await process.wait()
                with SessionLocal() as db:
                    job = db.get(ScanJob, scan_id)
                    job.exit_code = code; job.ended_at = utcnow()
                    job.status = "stopped" if job.stopped else ("completed" if code == 0 else "failed")
                    self._artifact(db, job.id, stdout_path, "stdout")
                    if stderr_path.stat().st_size:
                        self._artifact(db, job.id, stderr_path, "stderr")
                    xml_path = output_base.with_suffix(".xml")
                    if xml_path.exists():
                        ingest_xml(db, job, db.get(Target, job.target_id),
                                   db.get(Project, job.project_id),
                                   xml_path.read_bytes(), xml_path.name)
                    for suffix, kind in ((".nmap", "normal"), (".gnmap", "grepable")):
                        path = output_base.with_suffix(suffix)
                        if path.exists(): self._artifact(db, job.id, path, kind)
                    db.commit()
                    status = job.status
                await self._publish(scan_id, {
                    "stream": "status", "status": status, "exit_code": code})
            except Exception as exc:
                with SessionLocal() as db:
                    job = db.get(ScanJob, scan_id)
                    if job:
                        job.status = "failed"; job.error = str(exc)
                        job.ended_at = utcnow(); db.commit()
                await self._publish(scan_id, {
                    "stream": "status", "status": "failed", "error": str(exc)})
            finally:
                self.processes.pop(scan_id, None); self.tasks.pop(scan_id, None)

    @staticmethod
    def _artifact(db, scan_id: int, path: Path, kind: str) -> None:
        if db.query(ScanArtifact).filter_by(
                scan_job_id=scan_id, kind=kind, path=str(path)).first():
            return
        content = path.read_bytes()
        db.add(ScanArtifact(scan_job_id=scan_id, kind=kind, path=str(path),
                            sha256=hashlib.sha256(content).hexdigest(),
                            size=len(content), original_name=path.name))

    async def stop(self, scan_id: int) -> bool:
        with SessionLocal() as db:
            job = db.get(ScanJob, scan_id)
            if not job or job.status not in ("queued", "running"):
                return False
            job.stopped = True; job.status = "stopped"; job.ended_at = utcnow()
            db.commit()
        task, process = self.tasks.get(scan_id), self.processes.get(scan_id)
        if process and process.returncode is None:
            if os.name == "posix": os.killpg(process.pid, signal.SIGTERM)
            else: process.terminate()
            try: await asyncio.wait_for(process.wait(), 3)
            except asyncio.TimeoutError:
                if os.name == "posix": os.killpg(process.pid, signal.SIGKILL)
                else: process.kill()
        elif task:
            task.cancel()
        await self._publish(scan_id, {"stream": "status", "status": "stopped"})
        return True

    async def shutdown(self) -> None:
        for scan_id in list(self.tasks):
            await self.stop(scan_id)

manager = ScanManager()

def recover_interrupted_jobs() -> int:
    """Close jobs that cannot still own a process after an application restart."""
    with SessionLocal() as db:
        jobs = db.query(ScanJob).filter(ScanJob.status.in_(("queued", "running"))).all()
        for job in jobs:
            target, project = db.get(Target, job.target_id), db.get(Project, job.project_id)
            folder = scan_directory(project, target, job.id)
            for path, kind in (
                (folder / "stdout.txt", "stdout"),
                (folder / "stderr.txt", "stderr"),
                (folder / "nmap.xml", "xml"),
                (folder / "nmap.nmap", "normal"),
                (folder / "nmap.gnmap", "grepable"),
            ):
                if path.is_file():
                    ScanManager._artifact(db, job.id, path, kind)
            job.status = "interrupted"
            job.error = "Application restarted before the scan completed"
            job.ended_at = utcnow()
        db.commit()
        return len(jobs)
