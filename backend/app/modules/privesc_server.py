"""On-demand static file server for privilege-escalation scripts
(LinPEAS/WinPEAS/pspy).

The main API is loopback-only by design (see ARCHITECTURE.md); a target
machine still needs to reach these files over the VPN, so this runs as a
separate subprocess bound only to tun0, never on the main app's socket.

`python -m http.server` serves exactly one directory tree, but PEASS
(/usr/share/peass) and pspy (/usr/share/pspy) are two unrelated system
packages. Rather than run two servers/ports, a small staging directory under
this app's own data dir holds one symlink per available toolset, and that
staging directory is what actually gets served.
"""
from __future__ import annotations

import re
import socket
import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException

from ..config import DATA_DIR
from .vpn import vpn_status

router = APIRouter(prefix="/api/privesc-server", tags=["Privesc Server"])

PEASS_DIR = Path("/usr/share/peass")
PSPY_DIR = Path("/usr/share/pspy")
TOOLSETS = {"peass": PEASS_DIR, "pspy": PSPY_DIR}
STAGE_DIR = DATA_DIR / "privesc-serve"

_process: subprocess.Popen | None = None
_port: int | None = None


def _process_match() -> list[str]:
    return ["--directory", str(STAGE_DIR)]


def _tun0_ip() -> str:
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+", vpn_status().get("tun0", ""))
    if not match:
        raise HTTPException(409, "tun0가 연결되어 있지 않습니다")
    return match.group(1)


def _free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def _available() -> dict[str, bool]:
    return {name: path.is_dir() for name, path in TOOLSETS.items()}


def _stage() -> dict[str, bool]:
    """(Re)build STAGE_DIR so it holds exactly one symlink per toolset that
    is currently installed, and none for toolsets that are not."""
    STAGE_DIR.mkdir(parents=True, exist_ok=True)
    available = _available()
    for name, path in TOOLSETS.items():
        link = STAGE_DIR / name
        if link.is_symlink() or link.exists():
            link.unlink()
        if available[name]:
            link.symlink_to(path)
    return available


def kill_orphaned_server() -> None:
    """Best-effort cleanup for a server left running by a previous process
    generation (e.g. uvicorn --reload), since the PID lives only in memory."""
    try:
        subprocess.run(["/usr/bin/pkill", "-f", " ".join(_process_match())],
                        capture_output=True, timeout=2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _running() -> bool:
    return bool(_process and _process.poll() is None)


def _state() -> dict:
    if not _running():
        return {"running": False, "available": _available()}
    return {"running": True, "port": _port, "base_url": f"http://{_tun0_ip()}:{_port}",
            "available": _available()}


@router.post("/start")
def start_privesc_server():
    global _process, _port
    if _running():
        return _state()
    available = _stage()
    if not any(available.values()):
        raise HTTPException(409, "peass와 pspy 패키지가 모두 설치되어 있지 않습니다 "
                                  "(sudo apt install peass pspy)")
    host = _tun0_ip()
    port = _free_port(host)
    _process = subprocess.Popen(
        ["/usr/bin/python3", "-m", "http.server", str(port), "--bind", host,
         *_process_match()],
        start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _port = port
    return _state()


@router.post("/stop")
def stop_privesc_server():
    global _process, _port
    if _running():
        _process.terminate()
        try:
            _process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _process.kill()
    _process = None
    _port = None
    return _state()


@router.get("/status")
def privesc_server_status():
    return _state()
