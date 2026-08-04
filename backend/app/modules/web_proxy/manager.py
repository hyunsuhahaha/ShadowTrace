from __future__ import annotations
import asyncio
import ipaddress
import os
import signal
from pathlib import Path
from ...config import WORKSPACE_DIR
from ...database import SessionLocal
from ...models import Target

ADDON_PATH = Path(__file__).with_name("addon.py")
CONFDIR = WORKSPACE_DIR / "proxy" / ".mitmproxy"
BACKEND_URL = os.getenv("OSCP_BACKEND_URL", "http://127.0.0.1:8000")
MITMDUMP_BIN = os.getenv("OSCP_MITMDUMP_BIN", "mitmdump")


class ProxyManager:
    """Runs mitmdump as a subprocess and lets the user stop/inspect it.

    Only one capture session runs at a time, matching the app's
    single-active-target workflow — starting a second one while one is
    already running is rejected rather than silently replacing it.
    """

    def __init__(self) -> None:
        self.process: asyncio.subprocess.Process | None = None
        self.meta: dict | None = None
        self._stderr_task: asyncio.Task | None = None
        self._stderr_lines: list[str] = []

    def status(self) -> dict:
        running = bool(self.process and self.process.returncode is None)
        return {"running": running, **(self.meta or {}),
                "stderr_tail": self._stderr_lines[-20:]}

    async def start(self, project_id: int, target_id: int, port: int) -> dict:
        if self.process and self.process.returncode is None:
            raise RuntimeError("프록시가 이미 실행 중입니다. 먼저 중지하세요.")
        with SessionLocal() as db:
            target = db.get(Target, target_id)
            if not target:
                raise ValueError("Target을 찾을 수 없습니다.")
            ip = target.ip
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("이 대상은 IP 주소가 아니라 프록시 캡처로 자동 필터링할 수 없습니다.")
        CONFDIR.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "OSCP_BACKEND_URL": BACKEND_URL,
               "OSCP_PROXY_TARGET_IP": ip,
               "OSCP_PROXY_PROJECT_ID": str(project_id),
               "OSCP_PROXY_TARGET_ID": str(target_id)}
        self._stderr_lines = []
        self.process = await asyncio.create_subprocess_exec(
            MITMDUMP_BIN, "-p", str(port), "--listen-host", "127.0.0.1",
            "--set", f"confdir={CONFDIR}", "-s", str(ADDON_PATH),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            start_new_session=True, env=env)
        self.meta = {"project_id": project_id, "target_id": target_id,
                     "target_ip": ip, "port": port}
        self._stderr_task = asyncio.create_task(self._pump_stderr())
        await asyncio.sleep(0.3)
        if self.process.returncode is not None:
            tail = list(self._stderr_lines)
            self.process = None
            self.meta = None
            raise RuntimeError("mitmdump가 바로 종료되었습니다: " +
                               (tail[-1] if tail else "원인을 알 수 없음"))
        return self.status()

    async def _pump_stderr(self) -> None:
        process = self.process
        if not process or not process.stderr:
            return
        while line := await process.stderr.readline():
            self._stderr_lines.append(line.decode(errors="replace").rstrip())
            self._stderr_lines[:] = self._stderr_lines[-200:]

    async def stop(self) -> dict:
        if self.process and self.process.returncode is None:
            if os.name == "posix":
                os.killpg(self.process.pid, signal.SIGTERM)
            else:
                self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 3)
            except asyncio.TimeoutError:
                if os.name == "posix":
                    os.killpg(self.process.pid, signal.SIGKILL)
                else:
                    self.process.kill()
        self.process = None
        self.meta = None
        return self.status()

    async def shutdown(self) -> None:
        await self.stop()


manager = ProxyManager()
