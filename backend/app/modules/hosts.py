import ipaddress
import os
import re
import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/hosts", tags=["hosts"])
HOSTS_PATH = Path("/etc/hosts")
MARKER_BEGIN = "# OSCP-WORKSPACE-BEGIN"
MARKER_END = "# OSCP-WORKSPACE-END"
HOSTNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class HostsSync(BaseModel):
    ip: str
    hostname: str = Field(min_length=1, max_length=253)


def _validate_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise HTTPException(400, "올바른 IPv4 주소가 아닙니다.")


def _validate_hostname(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or not HOSTNAME_PATTERN.fullmatch(candidate):
        raise HTTPException(400, "올바른 hostname이 아닙니다.")
    return candidate


def _split_block(lines: list[str]) -> tuple[list[str], dict[str, str], list[str]]:
    try:
        start = lines.index(MARKER_BEGIN)
        end = lines.index(MARKER_END, start)
    except ValueError:
        return lines, {}, []
    entries: dict[str, str] = {}
    for line in lines[start + 1:end]:
        parts = line.split()
        if len(parts) >= 2:
            entries[parts[1]] = parts[0]
    return lines[:start], entries, lines[end + 1:]


def _write_hosts(before: list[str], entries: dict[str, str], after: list[str]) -> None:
    if HOSTS_PATH.is_symlink():
        raise HTTPException(409, "/etc/hosts가 symlink입니다.")
    block = [MARKER_BEGIN] + [
        f"{ip}\t{hostname}" for hostname, ip in sorted(entries.items())
    ] + [MARKER_END]
    text = "\n".join([*before, *block, *after]) + "\n"
    fd, tmp = tempfile.mkstemp(dir=str(HOSTS_PATH.parent), prefix=".hosts-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        if HOSTS_PATH.exists():
            shutil.copymode(HOSTS_PATH, tmp)
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, HOSTS_PATH)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@router.post("/sync")
def sync_host(body: HostsSync):
    """Upsert a hostname -> IP mapping into the app-managed /etc/hosts block,
    so a box that was reset to a new IP overwrites its own stale entry
    instead of accumulating duplicates."""
    ip = _validate_ipv4(body.ip)
    hostname = _validate_hostname(body.hostname)
    lines = HOSTS_PATH.read_text(encoding="utf-8").splitlines() if HOSTS_PATH.is_file() else []
    before, entries, after = _split_block(lines)
    entries[hostname] = ip
    _write_hosts(before, entries, after)
    return {"hostname": hostname, "ip": ip, "entries": entries}


@router.get("/sync")
def list_synced_hosts():
    lines = HOSTS_PATH.read_text(encoding="utf-8").splitlines() if HOSTS_PATH.is_file() else []
    _, entries, _ = _split_block(lines)
    return {"entries": entries}


def remove_entries(hostnames: list[str]) -> dict[str, str]:
    """Drop hostnames from the app-managed block, e.g. once no target
    references them anymore (project deleted, target deleted, or hostname
    corrected)."""
    lines = HOSTS_PATH.read_text(encoding="utf-8").splitlines() if HOSTS_PATH.is_file() else []
    before, entries, after = _split_block(lines)
    changed = False
    for hostname in hostnames:
        key = hostname.strip().lower().rstrip(".")
        if key in entries:
            del entries[key]
            changed = True
    if changed:
        _write_hosts(before, entries, after)
    return entries


@router.delete("/sync")
def remove_host(hostname: str):
    return {"entries": remove_entries([hostname])}
