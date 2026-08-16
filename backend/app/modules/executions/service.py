import asyncio
import re
import shlex
import shutil
from datetime import datetime
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ...config import WORKSPACE_DIR
from ...executor import queues, run_execution
from ...models import Execution, Project, Service, Target
from ...templates import catalog
from ..core.support import safe_part

REPOSITORY_DIR = Path(__file__).resolve().parents[4]
SHELL_OPERATORS = {"|", "||", "&&", ";", ">", ">>", "<", "<<"}


def _bound_value_count(argv: list[str], value: str, numeric: bool = False) -> int:
    if not value:
        return 0
    pattern = re.compile(
        rf"(?<!\d){re.escape(value)}(?!\d)" if numeric else re.escape(value)
    )
    return sum(len(pattern.findall(argument)) for argument in argv)


def _validated_override(
    raw: str, base_argv: list[str], host: str, service: Service | None,
    context_values: tuple[str, ...] = (),
) -> tuple[str, list[str]]:
    try:
        argv = shlex.split(raw.strip())
    except ValueError as exc:
        raise HTTPException(400, f"Invalid command syntax: {exc}") from exc
    if not argv:
        raise HTTPException(400, "Command cannot be empty")
    if any(argument in SHELL_OPERATORS or re.match(r"^\d*(?:>|<)", argument)
           for argument in argv):
        raise HTTPException(400, "Shell operators require a separate shell session")
    if Path(argv[0]).name != Path(base_argv[0]).name:
        raise HTTPException(400, "ENGINE CHANGED · EXECUTION LOCKED")
    for value in {host, *context_values}:
        if _bound_value_count(argv, value) < _bound_value_count(base_argv, value):
            raise HTTPException(400, "TARGET CHANGED · EXECUTION LOCKED")
    if service:
        port = str(service.port)
        if (_bound_value_count(argv, port, numeric=True)
                < _bound_value_count(base_argv, port, numeric=True)):
            raise HTTPException(400, "SERVICE CHANGED · EXECUTION LOCKED")
    return raw.strip(), argv


def output_path_for(output_dir: Path, raw_filename: str, template_id: str) -> Path:
    if not raw_filename.strip():
        return output_dir / f"{datetime.now():%Y%m%d_%H%M%S}_{safe_part(template_id)}.txt"
    base = safe_part(raw_filename.strip())
    if base.lower().endswith(".txt"):
        base = base[:-4] or "output"
    candidate = output_dir / f"{base}.txt"
    counter = 2
    while candidate.exists():
        candidate = output_dir / f"{base}-{counter}.txt"
        counter += 1
    return candidate


def target_output_dir(project: Project, target: Target) -> Path:
    return (WORKSPACE_DIR / "projects" / safe_part(project.name) /
            "targets" / safe_part(target.ip) / "outputs")


async def _run_bounded(semaphore: asyncio.Semaphore, execution_id: int,
                        argv: list[str], cwd: Path, output: Path) -> None:
    async with semaphore:
        await run_execution(execution_id, argv, cwd, output)


def start_execution(
    db: Session, target: Target, project: Project, service: Service | None,
    template_id: str, variables: dict[str, str], run_as_root: bool = True,
    output_filename: str = "", output_subdir: str | None = None,
    command_override: str | None = None, graph_node_id: str | None = None,
    scan_job_id: int | None = None, semaphore: asyncio.Semaphore | None = None,
) -> Execution:
    target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                  "targets" / safe_part(target.ip))
    output_dir = target_dir / "outputs"
    if output_subdir:
        output_dir = output_dir / safe_part(output_subdir)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Sites that route by vhost (nearly all named HTTP hosts) refuse or
    # redirect requests addressed by bare IP, so HTTP-family commands need
    # the confirmed hostname once one exists -- everything else (SMB, LDAP,
    # RDP...) keeps hitting the IP directly since a hostname mismatch there
    # is far less likely to change the response.
    template = catalog.items.get(template_id)
    use_hostname = (
        target.hostname and template and template.get("service_key") == "http"
    )
    full_variables = {
        **variables,
        "host": target.hostname if use_hostname else target.ip,
        "target_dir": str(target_dir),
        "project_dir": str(target_dir.parents[1]),
        "output_dir": str(output_dir),
        "repo_dir": str(REPOSITORY_DIR),
    }
    if service:
        full_variables.update(
            port=str(service.port), protocol=service.protocol,
            scheme="https" if service.name == "https" else "http",
        )
    item, command, argv = catalog.render(template_id, full_variables)
    if command_override is not None:
        command, argv = _validated_override(
            command_override, argv, full_variables["host"], service, (target.ip,),
        )
    if not shutil.which(argv[0]):
        raise HTTPException(409, f"Tool not installed: {argv[0]}")
    if run_as_root:
        if not shutil.which("sudo"):
            raise HTTPException(409, "sudo is not installed")
        argv = ["sudo", "-n", *argv]
        command = shlex.join(argv)
    row = Execution(
        target_id=target.id, service_id=service.id if service else None,
        template_id=item["id"], command=command, cwd=str(target_dir),
        status="queued", graph_parent_node_id=graph_node_id,
        scan_job_id=scan_job_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    output = output_path_for(output_dir, output_filename, item["id"])
    queues[row.id] = asyncio.Queue()
    if semaphore is None:
        asyncio.create_task(run_execution(row.id, argv, target_dir, output))
    else:
        asyncio.create_task(_run_bounded(semaphore, row.id, argv, target_dir, output))
    return row
