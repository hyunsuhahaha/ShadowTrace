from __future__ import annotations
import asyncio
import os
import signal
from ...database import SessionLocal
from ...models import AutoReconRun
from ...time import utcnow
from .service import import_autorecon_run

# Much simpler than ScanManager (scan_center/manager.py): no chaining, no
# mid-flight XML/artifact registration -- one subprocess per run, and the
# entire results tree gets imported in one pass (import_autorecon_run) once
# it exits, rather than parsing anything while it's still running.
class AutoReconManager:
    def __init__(self, concurrency: int = 2, stream_limit: int = 2_000_000):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.stream_limit = stream_limit
        self.processes: dict[int, asyncio.subprocess.Process] = {}
        self.events: dict[int, set[asyncio.Queue]] = {}
        self.tasks: dict[int, asyncio.Task] = {}

    def enqueue(self, run_id: int, argv: list[str]) -> None:
        self.events.setdefault(run_id, set())
        task = asyncio.create_task(self._run(run_id, argv))
        self.tasks[run_id] = task
        task.add_done_callback(lambda _: self.tasks.pop(run_id, None))

    async def _publish(self, run_id: int, event: dict) -> None:
        for queue in tuple(self.events.get(run_id, set())):
            await queue.put(event)

    def subscribe(self, run_id: int) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self.events.setdefault(run_id, set()).add(queue)
        return queue

    def unsubscribe(self, run_id: int, queue: asyncio.Queue) -> None:
        subscribers = self.events.get(run_id)
        if subscribers:
            subscribers.discard(queue)

    async def _run(self, run_id: int, argv: list[str]) -> None:
        async with self.semaphore:
            with SessionLocal() as db:
                run = db.get(AutoReconRun, run_id)
                if not run or run.status == "stopped":
                    return
                run.status = "running"; run.started_at = utcnow(); db.commit()
            await self._publish(run_id, {"stream": "status", "status": "running"})
            streamed = 0
            stream_notice_sent = False
            try:
                # stdin MUST be DEVNULL, not inherited/PIPE-unset -- without a
                # real TTY on stdin, AutoRecon's keyboard-status thread calls
                # termios.tcgetattr() and crashes (confirmed live).
                process = await asyncio.create_subprocess_exec(
                    *argv, stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    start_new_session=True)
                self.processes[run_id] = process
                async def pump(stream, kind: str):
                    nonlocal streamed, stream_notice_sent
                    while line := await stream.readline():
                        if streamed < self.stream_limit:
                            streamed += len(line)
                            await self._publish(run_id, {
                                "stream": kind, "data": line.decode(errors="replace")})
                        elif not stream_notice_sent:
                            stream_notice_sent = True
                            await self._publish(run_id, {"stream": "stdout",
                                "data": "\n[live output limit reached]\n"})
                await asyncio.gather(pump(process.stdout, "stdout"), pump(process.stderr, "stderr"))
                code = await process.wait()
                with SessionLocal() as db:
                    run = db.get(AutoReconRun, run_id)
                    run.exit_code = code; run.ended_at = utcnow()
                    run.status = "stopped" if run.stopped else ("completed" if code == 0 else "failed")
                    # Import whatever's on disk regardless of exit code --
                    # AutoRecon can exit non-zero from a single flaky plugin
                    # while still producing plenty of useful output for the
                    # rest, and a stopped run may have partial results too.
                    run.imported_count = import_autorecon_run(db, run)
                    db.commit()
                    status = run.status
                await self._publish(run_id, {
                    "stream": "status", "status": status, "exit_code": code})
            except Exception as exc:
                with SessionLocal() as db:
                    run = db.get(AutoReconRun, run_id)
                    if run:
                        run.status = "failed"; run.error = str(exc)
                        run.ended_at = utcnow(); db.commit()
                await self._publish(run_id, {
                    "stream": "status", "status": "failed", "error": str(exc)})
            finally:
                self.processes.pop(run_id, None); self.tasks.pop(run_id, None)

    async def stop(self, run_id: int) -> bool:
        with SessionLocal() as db:
            run = db.get(AutoReconRun, run_id)
            if not run or run.status not in ("queued", "running"):
                return False
            run.stopped = True; run.status = "stopped"; run.ended_at = utcnow()
            db.commit()
        task, process = self.tasks.get(run_id), self.processes.get(run_id)
        if process and process.returncode is None:
            if os.name == "posix": os.killpg(process.pid, signal.SIGTERM)
            else: process.terminate()
            try: await asyncio.wait_for(process.wait(), 3)
            except asyncio.TimeoutError:
                if os.name == "posix": os.killpg(process.pid, signal.SIGKILL)
                else: process.kill()
        elif task:
            task.cancel()
        await self._publish(run_id, {"stream": "status", "status": "stopped"})
        return True

    async def shutdown(self) -> None:
        for run_id in list(self.tasks):
            await self.stop(run_id)

manager = AutoReconManager()

def recover_interrupted_runs() -> int:
    """Close runs that cannot still own a process after an application
    restart -- mirrors scan_center.manager.recover_interrupted_jobs."""
    with SessionLocal() as db:
        runs = db.query(AutoReconRun).filter(
            AutoReconRun.status.in_(("queued", "running"))).all()
        for run in runs:
            run.status = "interrupted"
            run.error = "Application restarted before the run completed"
            run.ended_at = utcnow()
        db.commit()
        return len(runs)
