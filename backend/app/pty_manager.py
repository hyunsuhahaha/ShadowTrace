from __future__ import annotations
import asyncio
import json
import os
import signal
import termios
from pathlib import Path
from fastapi import WebSocket
from .database import SessionLocal
from .models import InteractiveSession
from .time import utcnow


def _descendant_pids(root_pid: int) -> list[int]:
    """Walk /proc's PPid links to find every descendant of root_pid.

    killpg() alone misses processes sudo detaches into a fresh session --
    sudoers' `use_pty` (the Kali/Debian default) does exactly that for
    long-running children like `sudo responder`, so a killed PTY session
    left the actual Responder process orphaned and still holding its
    ports for every later listener to fight over."""
    parents: dict[int, int] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/status") as handle:
                for line in handle:
                    if line.startswith("PPid:"):
                        parents[int(entry)] = int(line.split()[1])
                        break
        except (OSError, ValueError):
            continue
    children: dict[int, list[int]] = {}
    for pid, ppid in parents.items():
        children.setdefault(ppid, []).append(pid)
    result: list[int] = []
    stack = [root_pid]
    while stack:
        for child in children.get(stack.pop(), []):
            result.append(child)
            stack.append(child)
    return result


def _terminate_tree(root_pid: int, sig: signal.Signals) -> None:
    for pid in [root_pid, *_descendant_pids(root_pid)]:
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
    try:
        os.killpg(root_pid, sig)
    except ProcessLookupError:
        pass


def _cancel_or_settle(task: asyncio.Task) -> None:
    """Cancel a still-running task, or retrieve+discard a finished one's
    exception so asyncio doesn't log "exception was never retrieved"."""
    if not task.done():
        task.cancel()
        return
    try:
        task.exception()
    except (asyncio.CancelledError, Exception):
        pass


class PtyManager:
    # A docked terminal panel that gets dragged to detach (or docked back via
    # "원위치") remounts the React component that owns the WebSocket -- the
    # old socket closes and a new one for the *same* session opens right
    # after, all within one UI gesture. Killing the process the instant a
    # socket disconnects (the old behaviour) turned every drag into a dead
    # shell. Instead, a session that loses its socket while its process is
    # still alive gets a short grace window: a reconnect within that window
    # reattaches to the same process instead of respawning, and only a
    # reconnect-free timeout actually kills it.
    RECONNECT_GRACE_SECONDS = 8

    def __init__(self):
        self.processes: dict[int, asyncio.subprocess.Process] = {}
        self.masters: dict[int, int] = {}
        self._grace_handles: dict[int, asyncio.TimerHandle] = {}
        # asyncio only keeps a bare create_task() result alive via whatever
        # holds a reference to it -- an orphaned Task object is fair game for
        # garbage collection mid-run, which would silently stop watching for
        # this process's exit and leave its DB row stuck at "running" forever.
        self._finalize_tasks: dict[int, asyncio.Task] = {}

    async def connect(self, session_id: int, argv: list[str],
                      cwd: Path, log_path: Path, websocket: WebSocket) -> None:
        await websocket.accept()
        reattaching = (session_id in self.processes
                       and self.processes[session_id].returncode is None)
        if reattaching:
            handle = self._grace_handles.pop(session_id, None)
            if handle:
                handle.cancel()
            process = self.processes[session_id]
            master = self.masters[session_id]
        else:
            master, slave = os.openpty()
            process = None
            try:
                env = os.environ.copy()
                env.update({
                    "TERM": "xterm-256color",
                    "COLORTERM": "truecolor",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                })
                process = await asyncio.create_subprocess_exec(
                    *argv, cwd=cwd, stdin=slave, stdout=slave, stderr=slave,
                    start_new_session=True, env=env)
            except Exception as exc:
                os.close(master)
                os.close(slave)
                with SessionLocal() as db:
                    row = db.get(InteractiveSession, session_id)
                    if row:
                        row.status = "failed"; row.error = str(exc)
                        row.ended_at = utcnow(); row.pid = None; db.commit()
                await websocket.close()
                return
            os.close(slave)
            self.processes[session_id] = process
            self.masters[session_id] = master
            with SessionLocal() as db:
                row = db.get(InteractiveSession, session_id)
                row.status = "running"; row.pid = process.pid
                row.started_at = utcnow(); row.log_path = str(log_path); db.commit()
            self._finalize_tasks[session_id] = asyncio.create_task(
                self._finalize_on_exit(session_id, process, master))

        async def output():
            loop = asyncio.get_running_loop()
            with log_path.open("ab") as log:
                while True:
                    try:
                        # ponytail: run_in_executor blocks a thread-pool
                        # worker on os.read() for as long as the pty stays
                        # silent; cancel() below can only reclaim that thread
                        # once it next wakes up (new data, or the process
                        # dying). Bounded by RECONNECT_GRACE_SECONDS in the
                        # common case -- upgrade to loop.add_reader() if an
                        # idle-listener thread pileup ever shows up for real.
                        data = await loop.run_in_executor(None, os.read, master, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    log.write(data); log.flush()
                    try:
                        await websocket.send_bytes(data)
                    except Exception:
                        break

        async def input_data():
            while True:
                message = await websocket.receive()
                if message.get("bytes") is not None:
                    os.write(master, message["bytes"])
                elif message.get("text"):
                    text = message["text"]
                    try:
                        control = json.loads(text)
                    except json.JSONDecodeError:
                        os.write(master, text.encode())
                        continue
                    if control.get("type") == "resize":
                        rows = max(1, min(int(control.get("rows", 24)), 200))
                        cols = max(1, min(int(control.get("cols", 80)), 400))
                        termios.tcsetwinsize(master, (rows, cols))

        output_task = asyncio.create_task(output())
        input_task = asyncio.create_task(input_data())
        process_task = asyncio.create_task(process.wait())
        done, _ = await asyncio.wait(
            {process_task, input_task, output_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        output_task.cancel()
        if process_task in done:
            # The process ended on its own (or was actually killed by
            # stop()/a prior grace timeout) -- finalize happens in
            # _finalize_on_exit, spawned once per real process. Just stop
            # talking to this websocket.
            _cancel_or_settle(input_task)
            await websocket.close()
            return
        # Only the socket went away, and the process is still running: give
        # it RECONNECT_GRACE_SECONDS to be reclaimed before actually killing.
        _cancel_or_settle(input_task)
        loop = asyncio.get_running_loop()

        def kill_after_grace():
            self._grace_handles.pop(session_id, None)
            if process.returncode is None:
                with SessionLocal() as db:
                    row = db.get(InteractiveSession, session_id)
                    if row:
                        row.status = "stopping"
                        db.commit()
                os.killpg(process.pid, signal.SIGTERM)

        self._grace_handles[session_id] = loop.call_later(
            self.RECONNECT_GRACE_SECONDS, kill_after_grace)

    async def _finalize_on_exit(self, session_id: int,
                                process: asyncio.subprocess.Process, master: int) -> None:
        code = await process.wait()
        handle = self._grace_handles.pop(session_id, None)
        if handle:
            handle.cancel()
        with SessionLocal() as db:
            row = db.get(InteractiveSession, session_id)
            if row:
                row.exit_code = code; row.ended_at = utcnow()
                row.status = "stopped" if row.status == "stopping" else (
                    "completed" if code == 0 else "failed")
                row.pid = None; db.commit()
        self.processes.pop(session_id, None)
        self.masters.pop(session_id, None)
        self._finalize_tasks.pop(session_id, None)
        try:
            os.close(master)
        except OSError:
            pass

    async def stop(self, session_id: int) -> bool:
        process = self.processes.get(session_id)
        if not process or process.returncode is not None:
            return False
        with SessionLocal() as db:
            row = db.get(InteractiveSession, session_id)
            if row:
                row.status = "stopping"; db.commit()
        _terminate_tree(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 3)
        except asyncio.TimeoutError:
            _terminate_tree(process.pid, signal.SIGKILL)
        return True

    async def shutdown(self) -> None:
        for session_id in list(self.processes):
            await self.stop(session_id)


pty_manager = PtyManager()
