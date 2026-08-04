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


class PtyManager:
    def __init__(self):
        self.processes: dict[int, asyncio.subprocess.Process] = {}
        self.masters: dict[int, int] = {}

    async def connect(self, session_id: int, argv: list[str],
                      cwd: Path, log_path: Path, websocket: WebSocket) -> None:
        await websocket.accept()
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
            os.close(slave)
            self.processes[session_id] = process
            self.masters[session_id] = master
            with SessionLocal() as db:
                row = db.get(InteractiveSession, session_id)
                row.status = "running"; row.pid = process.pid
                row.started_at = utcnow(); row.log_path = str(log_path); db.commit()

            async def output():
                loop = asyncio.get_running_loop()
                with log_path.open("ab") as log:
                    while True:
                        try:
                            data = await loop.run_in_executor(None, os.read, master, 4096)
                        except OSError:
                            break
                        if not data:
                            break
                        log.write(data); log.flush()
                        await websocket.send_bytes(data)

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
                {process_task, input_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if input_task in done and process.returncode is None:
                with SessionLocal() as db:
                    row = db.get(InteractiveSession, session_id)
                    if row:
                        row.status = "stopping"
                        db.commit()
                os.killpg(process.pid, signal.SIGTERM)
            code = await process_task
            await output_task
            if not input_task.done():
                input_task.cancel()
            else:
                try:
                    input_task.exception()
                except (asyncio.CancelledError, Exception):
                    pass
            with SessionLocal() as db:
                row = db.get(InteractiveSession, session_id)
                row.exit_code = code; row.ended_at = utcnow()
                row.status = "stopped" if row.status == "stopping" else (
                    "completed" if code == 0 else "failed")
                row.pid = None; db.commit()
            await websocket.close()
        except Exception as exc:
            with SessionLocal() as db:
                row = db.get(InteractiveSession, session_id)
                if row:
                    row.status = "failed"; row.error = str(exc)
                    row.ended_at = utcnow(); row.pid = None; db.commit()
        finally:
            if process and process.returncode is None:
                _terminate_tree(process.pid, signal.SIGTERM)
            self.processes.pop(session_id, None)
            self.masters.pop(session_id, None)
            try:
                os.close(master)
            except OSError:
                pass
            try:
                os.close(slave)
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
