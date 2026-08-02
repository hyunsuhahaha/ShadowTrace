import hashlib
import os
import re
import secrets
import subprocess
import tempfile
import threading
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from ..config import CONFIG_DIR

router = APIRouter(prefix="/api/vpn", tags=["vpn"])
VPN_DIR = CONFIG_DIR / "vpn"
CONFIG_PATH = VPN_DIR / "selected.ovpn"
UUID_FILE = VPN_DIR / "active-connection"
NMCLI = "/usr/bin/nmcli"
MAX_CONFIG_SIZE = 2 * 1024 * 1024
UUID_PATTERN = re.compile(r"^[0-9a-fA-F-]{36}$")
UNSAFE_DIRECTIVES = {
    "up", "down", "route-up", "ipchange", "learn-address", "tls-verify",
    "auth-user-pass-verify", "client-connect", "client-disconnect",
    "plugin", "script-security",
}
FILE_OPTIONS = {
    "ca", "cert", "key", "pkcs12", "secret", "tls-auth", "tls-crypt",
    "crl-verify",
}
_approval_lock = threading.Lock()
_approvals: dict[str, dict] = {}


class VpnApproval(BaseModel):
    approval_token: str = Field(min_length=32, max_length=200)


def _run(argv: list[str], timeout: int = 30) -> dict:
    action = argv[2] if len(argv) > 2 else argv[0]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            check=False, shell=False)
        return {
            "action": action, "argv": argv, "stdout": completed.stdout,
            "stderr": completed.stderr, "exit_code": completed.returncode,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "action": action, "argv": argv, "stdout": exc.stdout or "",
            "stderr": exc.stderr or "Operation timed out.", "exit_code": 124,
        }


def validate_ovpn(content: bytes) -> str:
    if not content or len(content) > MAX_CONFIG_SIZE:
        raise HTTPException(400, "OVPN 파일은 1 byte 이상 2 MiB 이하여야 합니다.")
    if b"\x00" in content:
        raise HTTPException(400, "텍스트 형식의 OVPN 파일만 사용할 수 있습니다.")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "UTF-8 형식의 OVPN 파일만 사용할 수 있습니다.") from exc
    entries = [
        line.split()
        for raw in text.splitlines()
        if (line := raw.strip()) and not line.startswith(("#", ";", "<"))
    ]
    directives = {entry[0].lower() for entry in entries}
    if not {"client", "remote"}.issubset(directives):
        raise HTTPException(400, "OpenVPN client 설정과 remote 항목이 필요합니다.")
    blocked = directives & UNSAFE_DIRECTIVES
    blocked |= {
        entry[0].lower() for entry in entries
        if len(entry) > 1 and (
            entry[0].lower() in FILE_OPTIONS
            or entry[0].lower() == "auth-user-pass")
    }
    if blocked:
        raise HTTPException(
            400, "외부 명령이나 외부 파일을 사용하는 OVPN 옵션은 허용하지 않습니다: "
            + ", ".join(sorted(blocked)))
    return text


def _config_file() -> Path:
    if (CONFIG_PATH.is_symlink() or VPN_DIR.is_symlink()
            or CONFIG_PATH.resolve(strict=True) != CONFIG_PATH):
        raise HTTPException(409, "VPN 설정 경로의 symlink가 감지되었습니다.")
    if not CONFIG_PATH.is_file() or CONFIG_PATH.stat().st_size > MAX_CONFIG_SIZE:
        raise HTTPException(409, "승인할 VPN 설정 파일을 찾을 수 없습니다.")
    return CONFIG_PATH


def _saved_uuid() -> str:
    if not UUID_FILE.is_file() or UUID_FILE.is_symlink():
        return ""
    value = UUID_FILE.read_text(encoding="utf-8").strip()
    return value if UUID_PATTERN.fullmatch(value) else ""


def _status_operation() -> dict:
    connection_uuid = _saved_uuid()
    if not connection_uuid:
        return {
            "action": "status", "argv": [NMCLI, "connection", "show"],
            "stdout": "", "stderr": "", "exit_code": 0,
        }
    return _run([
        NMCLI, "-g", "GENERAL.NAME,GENERAL.STATE",
        "connection", "show", "uuid", connection_uuid], timeout=3)


def _tun0_link_type() -> str:
    """"tun" (no Ethernet/ARP layer, e.g. most OpenVPN configs) or "tap"
    (has a MAC address, so raw-Ethernet tools like masscan can use it)."""
    result = _run(["/usr/sbin/ip", "-d", "link", "show", "tun0"], timeout=2)
    if result["exit_code"] != 0:
        return ""
    output = result["stdout"]
    if "link/ether" in output:
        return "tap"
    if "link/none" in output:
        return "tun"
    return ""


def vpn_status() -> dict:
    operation = _status_operation()
    values = operation["stdout"].splitlines() if operation["exit_code"] == 0 else []
    state = values[1].lower() if len(values) > 1 else ""
    addr = _run(["/usr/sbin/ip", "-brief", "addr", "show", "tun0"], timeout=2)
    routes = _run(["/usr/sbin/ip", "route"], timeout=2)
    return {
        "connected": "activated" in state or bool(addr["stdout"].strip()),
        "tun0": addr["stdout"].strip(),
        "link_type": _tun0_link_type(),
        "routes": routes["stdout"].splitlines()[:8],
        "connection_name": values[0] if values else "",
        "operation": operation,
    }


@router.get("/status")
def get_vpn_status():
    return vpn_status()


@router.post("/prepare")
async def prepare_vpn(file: UploadFile = File(...)):
    supplied = file.filename or ""
    if (not supplied.lower().endswith(".ovpn") or "/" in supplied
            or "\\" in supplied or Path(supplied).name != supplied):
        raise HTTPException(400, "경로가 없는 .ovpn 파일만 선택할 수 있습니다.")
    content = await file.read(MAX_CONFIG_SIZE + 1)
    validate_ovpn(content)
    VPN_DIR.mkdir(parents=True, exist_ok=True, mode=0o770)
    if VPN_DIR.is_symlink() or VPN_DIR.resolve() != VPN_DIR:
        raise HTTPException(400, "VPN 저장 경로에 symlink를 사용할 수 없습니다.")
    os.chmod(VPN_DIR, 0o770)
    fd, temporary = tempfile.mkstemp(prefix=".selected-", dir=VPN_DIR)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
        os.chmod(temporary, 0o660)
        os.replace(temporary, CONFIG_PATH)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    digest = hashlib.sha256(content).hexdigest()
    profile_name = f"oscp-workspace-{digest[:12]}"
    token = secrets.token_urlsafe(32)
    with _approval_lock:
        _approvals[token] = {
            "sha256": digest, "profile_name": profile_name,
            "file_name": supplied,
        }
    return {
        "approval_token": token, "file_name": supplied, "sha256": digest,
        "profile_name": profile_name,
        "actions": ["NetworkManager profile import", "profile name set",
                    "VPN connection up"],
    }


@router.post("/connect")
def connect_vpn(body: VpnApproval):
    with _approval_lock:
        approved = _approvals.pop(body.approval_token, None)
    if not approved:
        raise HTTPException(409, "VPN 승인이 없거나 이미 사용되었습니다.")
    path = _config_file()
    current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if current_hash != approved["sha256"]:
        raise HTTPException(409, "OVPN 파일이 변경되었습니다. 다시 검토해 주세요.")
    operations = []
    imported = _run([
        NMCLI, "connection", "import", "type", "openvpn", "file", str(path)])
    operations.append(imported)
    if imported["exit_code"] != 0:
        status = vpn_status(); status["operations"] = operations
        return status
    match = re.search(r"\(([0-9a-fA-F-]{36})\)", imported["stdout"])
    if not match:
        imported["stderr"] += "Imported profile UUID was not returned.\n"
        imported["exit_code"] = 1
        status = vpn_status(); status["operations"] = operations
        return status
    connection_uuid = match.group(1)
    renamed = _run([
        NMCLI, "connection", "modify", "uuid", connection_uuid,
        "connection.id", approved["profile_name"],
        "ipv4.never-default", "yes",
        "ipv6.never-default", "yes"])
    operations.append(renamed)
    if renamed["exit_code"] != 0:
        operations.append(_run([
            NMCLI, "connection", "delete", "uuid", connection_uuid]))
        status = vpn_status(); status["operations"] = operations
        return status
    connected = _run([
        NMCLI, "connection", "up", "uuid", connection_uuid], timeout=60)
    operations.append(connected)
    if connected["exit_code"] != 0:
        operations.append(_run([
            NMCLI, "connection", "delete", "uuid", connection_uuid]))
        status = vpn_status(); status["operations"] = operations
        return status
    previous = _saved_uuid()
    if previous and previous != connection_uuid:
        operations.append(_run([
            NMCLI, "connection", "down", "uuid", previous]))
        operations.append(_run([
            NMCLI, "connection", "delete", "uuid", previous]))
    UUID_FILE.write_text(connection_uuid, encoding="utf-8")
    os.chmod(UUID_FILE, 0o660)
    status = vpn_status(); status["operations"] = operations
    return status


def _disconnect() -> dict:
    connection_uuid = _saved_uuid()
    if not connection_uuid:
        return {
            "action": "down", "argv": [NMCLI, "connection", "down"],
            "stdout": "", "stderr": "No app-managed VPN profile.\n",
            "exit_code": 0,
        }
    return _run([
        NMCLI, "connection", "down", "uuid", connection_uuid])


@router.post("/disconnect")
def disconnect_vpn():
    operation = _disconnect()
    status = vpn_status(); status["operations"] = [operation]
    return status

