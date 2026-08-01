from pathlib import Path
import json
import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ...models import (
    RunbookStepTemplate, RunbookTemplate, RunbookTemplateVersion,
)
from ...templates import catalog
from ...time import utcnow

SOURCE = Path(__file__).parents[3] / "templates" / "runbooks.yaml"


def ensure_builtin_runbooks(db: Session) -> int:
    data = yaml.safe_load(SOURCE.read_text(encoding="utf-8")) or {}
    installed = 0
    for item in data.get("runbooks", []):
        key = item["key"]
        revision = int(item["revision"])
        row = db.scalar(select(RunbookTemplate).where(
            RunbookTemplate.builtin_key == key))
        if not row:
            row = RunbookTemplate(
                name=item["name"], description=item.get("description", ""),
                tags=json.dumps(item.get("tags", []), ensure_ascii=False),
                service_names=json.dumps(item.get("service_names", [])),
                ports=json.dumps(item.get("ports", [])), origin="builtin",
                builtin_key=key)
            db.add(row); db.flush()
        current = db.scalar(select(func.max(RunbookTemplateVersion.version)).where(
            RunbookTemplateVersion.template_id == row.id)) or 0
        if current >= revision:
            continue
        steps = item.get("steps", [])
        node_keys = [step.get("node_key") or step.get("guidance", {}).get("stage_id")
                     or f"step-{position}"
                     for position, step in enumerate(steps, 1)]
        if len(node_keys) != len(set(node_keys)):
            raise RuntimeError(f"Built-in runbook {key} has duplicate node keys")
        referenced = {
            target for step in steps for transition in step.get("transitions", [])
            for target in ([transition.get("target")]
                           if transition.get("target") else transition.get("targets", []))
        }
        unknown_targets = sorted(referenced - set(node_keys))
        if unknown_targets:
            raise RuntimeError(
                f"Built-in runbook {key} references unknown nodes: {unknown_targets}")
        missing = sorted({
            ref for step in steps for ref in step.get("command_refs", [])
            if ref not in catalog.items
        })
        if missing:
            raise RuntimeError(
                f"Built-in runbook {key} references unknown commands: {missing}")
        row.name = item["name"]
        row.description = item.get("description", "")
        row.tags = json.dumps(item.get("tags", []), ensure_ascii=False)
        row.service_names = json.dumps(item.get("service_names", []))
        row.ports = json.dumps(item.get("ports", []))
        row.updated_at = utcnow()
        version = RunbookTemplateVersion(
            template_id=row.id, version=revision, name=row.name,
            description=row.description, tags=row.tags,
            service_names=row.service_names, ports=row.ports)
        db.add(version); db.flush()
        for position, step in enumerate(steps, 1):
            db.add(RunbookStepTemplate(
                version_id=version.id, position=position, title=step["title"],
                description=step.get("description", ""),
                command_refs=json.dumps(step.get("command_refs", [])),
                expected_observations=json.dumps(
                    step.get("expected_observations", []), ensure_ascii=False),
                condition=json.dumps(step.get("condition", {})),
                guidance=json.dumps(step.get("guidance", {}), ensure_ascii=False),
                node_key=step.get("node_key")
                or step.get("guidance", {}).get("stage_id")
                or f"step-{position}",
                node_type=step.get("node_type", "command" if step.get(
                    "command_refs") else "manual_check"),
                transitions=json.dumps(step.get("transitions", []),
                                       ensure_ascii=False),
                error_policy=json.dumps(step.get("error_policy", {}),
                                        ensure_ascii=False),
                approval=json.dumps(step.get("approval", {}),
                                    ensure_ascii=False)))
        installed += 1
    db.commit()
    return installed
