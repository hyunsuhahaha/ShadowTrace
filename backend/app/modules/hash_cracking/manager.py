from __future__ import annotations
import asyncio
import hashlib
import os
import signal
from pathlib import Path
from ...database import SessionLocal
from ...models import Evidence, HashCrackJob, Project, Target
from ...time import utcnow

# hashcat exits 0 when every hash cracked, 1 when it exhausted the wordlist
# (and rules) without cracking all of them — that is a normal, non-error
# outcome, not a failure.
OK_EXIT_CODES = {0, 1}


def parse_cracked(cracked_path: Path) -> list[dict]:
    if not cracked_path.is_file():
        return []
    results = []
    for line in cracked_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        hash_part, _, plain = line.rpartition(":")
        results.append({"hash": hash_part, "plain": plain})
    return results


def _parse_john_show(output: str) -> list[dict]:
    """`john --show` doesn't write hash:plain the way hashcat's own -o does
    -- its line shape varies by format (NT: "lmhash:plain", ZIP:
    "name:plain::archive:entries:path", ...), but every format shares the
    same first-two-fields structure: identifier, then plaintext, then
    optional trailing metadata. Splitting on the first colon and taking the
    next field (not rpartition -- ZIP's trailing fields would eat the
    plaintext) recovers a hash:plain pair in every format observed, so this
    writes straight into cracked_path in parse_cracked()'s own shape and
    every downstream consumer (Inspector's cracked list, promote, evidence
    capture) stays unchanged."""
    results = []
    for line in output.splitlines():
        if ":" not in line or "password hash" in line:
            continue
        identifier, _, rest = line.partition(":")
        plain = rest.split(":")[0]
        if identifier and plain:
            results.append({"hash": identifier, "plain": plain})
    return results


class HashCrackManager:
    def __init__(self, stream_limit: int = 2_000_000):
        self.stream_limit = stream_limit
        self.processes: dict[int, asyncio.subprocess.Process] = {}
        self.cancel_events: dict[int, asyncio.Event] = {}
        self.events: dict[int, set[asyncio.Queue]] = {}
        self.tasks: dict[int, asyncio.Task] = {}

    def enqueue(self, job_id: int, argv: list[str], folder: Path,
                engine: str = "hashcat", john_format: str = "") -> None:
        self.events.setdefault(job_id, set())
        self.cancel_events[job_id] = asyncio.Event()
        task = asyncio.create_task(self._run(job_id, argv, folder, engine, john_format))
        self.tasks[job_id] = task
        task.add_done_callback(lambda _: self.tasks.pop(job_id, None))

    async def _publish(self, job_id: int, event: dict) -> None:
        for queue in tuple(self.events.get(job_id, set())):
            await queue.put(event)

    def subscribe(self, job_id: int) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self.events.setdefault(job_id, set()).add(queue)
        return queue

    def unsubscribe(self, job_id: int, queue: asyncio.Queue) -> None:
        subscribers = self.events.get(job_id)
        if subscribers:
            subscribers.discard(queue)

    async def _spawn_and_pump(self, job_id: int, argv: list[str], folder: Path,
                              stdout_path: Path, stderr_path: Path,
                              cancel_event: asyncio.Event) -> tuple[int, bool]:
        streamed = 0
        # Mesa's rusticl OpenCL platform (the CPU fallback on a GPU-less
        # box — a VM, most often) enumerates zero devices unless this is
        # set; a real GPU backend (CUDA/HIP/a genuine OpenCL ICD) is
        # unaffected either way, so it's safe to always set.
        env = {**os.environ, "RUSTICL_ENABLE": "llvmpipe"}
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=folder, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True, env=env)
        self.processes[job_id] = process

        async def pump(stream, path: Path, kind: str):
            nonlocal streamed
            with path.open("wb") as output:
                while line := await stream.readline():
                    output.write(line); output.flush()
                    if streamed < self.stream_limit:
                        streamed += len(line)
                        await self._publish(job_id, {
                            "stream": kind, "data": line.decode(errors="replace")})

        pump_task = asyncio.ensure_future(asyncio.gather(
            pump(process.stdout, stdout_path, "stdout"),
            pump(process.stderr, stderr_path, "stderr")))
        process_task = asyncio.ensure_future(process.wait())
        cancel_task = asyncio.ensure_future(cancel_event.wait())
        done, _ = await asyncio.wait({process_task, cancel_task},
                                     return_when=asyncio.FIRST_COMPLETED)
        cancelled = False
        if process_task not in done:
            cancelled = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(process_task, timeout=3)
            except asyncio.TimeoutError:
                os.killpg(process.pid, signal.SIGKILL)
                await process_task
        cancel_task.cancel()
        await pump_task
        self.processes.pop(job_id, None)
        return process.returncode, cancelled

    @staticmethod
    async def _write_john_cracked(folder: Path, john_format: str, cracked_path: Path) -> None:
        """john writes cracked pairs to its own global potfile (~/.john/
        john.pot), not to a file this job controls the way hashcat's -o
        does -- --show reads them back out keyed by the exact hashes.txt
        this job already wrote, including anything already cracked in a
        previous run (a deliberate cross-job cache, not a bug: john has no
        hashcat-style single-instance lock forcing job isolation in the
        first place). Re-derives the same hash:plain shape hashcat's -o
        already produces so every downstream consumer needs no changes."""
        process = await asyncio.create_subprocess_exec(
            "john", "--show", f"--format={john_format}", "hashes.txt",
            cwd=folder, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await process.communicate()
        cracked = _parse_john_show(stdout.decode(errors="replace"))
        cracked_path.write_text(
            "\n".join(f"{item['hash']}:{item['plain']}" for item in cracked), encoding="utf-8")

    @staticmethod
    def _is_self_test_failure(stderr_path: Path) -> bool:
        if not stderr_path.is_file():
            return False
        return "kernel self-test failed" in stderr_path.read_text(
            encoding="utf-8", errors="replace").lower()

    async def _run(self, job_id: int, argv: list[str], folder: Path,
                    engine: str = "hashcat", john_format: str = "") -> None:
        folder.mkdir(parents=True, exist_ok=True)
        stdout_path, stderr_path = folder / "stdout.txt", folder / "stderr.txt"
        cracked_path = folder / "cracked.txt"
        await self._publish(job_id, {"stream": "status", "status": "running"})
        cancel_event = self.cancel_events[job_id]
        try:
            code, cancelled = await self._spawn_and_pump(
                job_id, argv, folder, stdout_path, stderr_path, cancel_event)
            if (engine == "hashcat" and not cancelled and code not in OK_EXIT_CODES
                    and "--self-test-disable" not in argv
                    and self._is_self_test_failure(stderr_path)):
                # Confirmed live: Mesa's software OpenCL (llvmpipe/rusticl)
                # kernel doesn't pass its own self-test for some algorithms
                # (PKZIP's pure kernel, seen here) even though the actual
                # attack runs and parses hashes fine once self-test is
                # skipped -- hashcat's own error message names this exact
                # flag as the sanctioned override, so retry once with it
                # rather than reporting a driver limitation as a cracking
                # failure.
                code, cancelled = await self._spawn_and_pump(
                    job_id, [*argv, "--self-test-disable"], folder,
                    stdout_path, stderr_path, cancel_event)
            if engine == "john" and not cancelled and code in OK_EXIT_CODES:
                await self._write_john_cracked(folder, john_format, cracked_path)
            cracked = parse_cracked(cracked_path)
            with SessionLocal() as db:
                job = db.get(HashCrackJob, job_id)
                job.exit_code = code
                job.ended_at = utcnow()
                job.cancelled = cancelled
                job.cracked_count = len(cracked)
                job.status = (
                    "cancelled" if cancelled else
                    "completed" if code in OK_EXIT_CODES else "failed")
                target = db.get(Target, job.target_id)
                project = db.get(Project, job.project_id)
                self._capture_evidence(db, job, project, target, stdout_path,
                                       stderr_path, cracked)
                db.commit()
                status = job.status
            await self._publish(job_id, {
                "stream": "status", "status": status, "exit_code": code,
                "cracked_count": len(cracked)})
        except Exception as exc:
            with SessionLocal() as db:
                job = db.get(HashCrackJob, job_id)
                if job:
                    job.status = "failed"; job.error = str(exc)
                    job.ended_at = utcnow()
                    if not stderr_path.is_file() or not stderr_path.read_text(
                            encoding="utf-8", errors="replace").strip():
                        stderr_path.write_text(str(exc), encoding="utf-8")
                    target = db.get(Target, job.target_id)
                    project = db.get(Project, job.project_id)
                    self._capture_evidence(db, job, project, target,
                                           stdout_path, stderr_path,
                                           parse_cracked(cracked_path))
                    db.commit()
            await self._publish(job_id, {
                "stream": "status", "status": "failed", "error": str(exc)})
        finally:
            self.processes.pop(job_id, None)
            self.cancel_events.pop(job_id, None)

    @staticmethod
    def _capture_evidence(db, job: HashCrackJob, project: Project, target: Target,
                          stdout_path: Path, stderr_path: Path, cracked: list[dict]) -> None:
        summary = "\n".join(f"{item['hash']} : {item['plain']}" for item in cracked)
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.is_file() else ""
        content = (f"{job.hash_type_name} · {job.hash_count}개 해시 중 {len(cracked)}개 크랙\n\n"
                  f"{summary}" + (f"\n\n[stderr]\n{stderr_text}" if stderr_text else ""))
        output_path = stdout_path.parent / "output.txt"
        output_path.write_text(content, encoding="utf-8")
        evidence = Evidence(
            project_id=project.id, target_id=target.id,
            title=f"Hash crack #{job.id}: {job.hash_type_name}",
            description=job.command_display,
            kind="command_output", source_type="hash_crack_job",
            source_id=job.id, file_path=str(output_path),
            original_name=output_path.name,
            sha256=hashlib.sha256(content.encode()).hexdigest(),
            size=len(content.encode()), hostname=target.hostname or target.ip,
            sensitivity="sensitive", include_report=False,
        )
        db.add(evidence); db.flush()
        job.evidence_id = evidence.id

    async def cancel(self, job_id: int) -> bool:
        event = self.cancel_events.get(job_id)
        if not event:
            return False
        event.set()
        return True

    async def shutdown(self) -> None:
        for job_id in list(self.cancel_events):
            await self.cancel(job_id)


manager = HashCrackManager()
