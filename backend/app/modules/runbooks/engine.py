"""Deterministic, inspectable branching for Runbook instances."""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import Credential, RunbookInstance, RunbookStepInstance


TERMINAL_STATUSES = {"completed", "skipped", "not_applicable"}
RESOLVED_OUTCOMES = {
    "confirmed", "not_found", "access_denied", "authentication_required",
    "partial", "not_applicable", "error", "needs_review", "ambiguous",
}


def json_value(value: str | None, fallback: Any) -> Any:
    try:
        parsed = json.loads(value or "")
        return parsed
    except (TypeError, json.JSONDecodeError):
        return fallback


def key_for(step: RunbookStepInstance) -> str:
    if step.node_key:
        return step.node_key
    guidance = json_value(step.guidance, {})
    return str(guidance.get("stage_id") or f"step-{step.position}")


def approval_required(step: RunbookStepInstance) -> bool:
    policy = json_value(step.approval, {})
    return step.node_type == "approval" or bool(policy.get("required"))


def resolved(step: RunbookStepInstance) -> bool:
    return (step.status in TERMINAL_STATUSES
            or step.outcome in RESOLVED_OUTCOMES
            or step.status in {"attempted", "blocked", "suspicious"})


def _fact_keys(steps: list[RunbookStepInstance]) -> set[str]:
    result: set[str] = set()
    for step in steps:
        assessment = json_value(step.assessment, {})
        for fact in assessment.get("facts", []):
            if isinstance(fact, dict) and fact.get("key"):
                result.add(str(fact["key"]))
    return result


def _matches(expected: Any, actual: Any) -> bool:
    return actual in expected if isinstance(expected, list) else actual == expected


def predicate_matches(predicate: dict, source: RunbookStepInstance,
                      *, facts: set[str], db: Session,
                      instance: RunbookInstance) -> bool:
    """Evaluate the deliberately small, non-executable transition DSL."""
    if not predicate:
        return False
    if "all" in predicate:
        return all(predicate_matches(item, source, facts=facts, db=db,
                                     instance=instance)
                   for item in predicate["all"])
    if "any" in predicate:
        return any(predicate_matches(item, source, facts=facts, db=db,
                                     instance=instance)
                   for item in predicate["any"])
    if "not" in predicate:
        return not predicate_matches(predicate["not"], source, facts=facts,
                                     db=db, instance=instance)
    checks = []
    if "always" in predicate:
        checks.append(bool(predicate["always"]))
    if "outcome" in predicate:
        checks.append(_matches(predicate["outcome"], source.outcome))
    if "status" in predicate:
        checks.append(_matches(predicate["status"], source.status))
    if "approval_status" in predicate:
        checks.append(_matches(predicate["approval_status"], source.approval_status))
    if "fact_exists" in predicate:
        wanted = predicate["fact_exists"]
        checks.append(any(item in facts for item in wanted)
                      if isinstance(wanted, list) else wanted in facts)
    if "credential_exists" in predicate:
        wanted = str(predicate["credential_exists"]).lower()
        credentials = db.scalars(select(Credential).where(
            Credential.project_id == instance.project_id)).all()
        checks.append(any(wanted in {
            str(value).lower() for value in json_value(row.service_names, [])
        } for row in credentials))
    return bool(checks) and all(checks)


def _transition_targets(transition: dict) -> list[str]:
    value = transition.get("targets", transition.get("target", []))
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value if item]


def _decision(step: RunbookStepInstance, transitions: list[dict], *,
              facts: set[str], db: Session,
              instance: RunbookInstance) -> tuple[list[str], dict, bool]:
    ordered = sorted(enumerate(transitions),
                     key=lambda item: (-int(item[1].get("priority", 0)), item[0]))
    default = None
    evaluated = []
    for _, transition in ordered:
        if transition.get("default"):
            default = transition
            continue
        matched = predicate_matches(
            transition.get("when", {}), step, facts=facts, db=db,
            instance=instance)
        evaluated.append({
            "label": transition.get("label", ""),
            "when": transition.get("when", {}), "matched": matched,
            "targets": _transition_targets(transition),
        })
        if matched:
            targets = _transition_targets(transition)
            return targets, {
                "selected": targets, "label": transition.get("label", ""),
                "reason": transition.get("when", {}), "evaluated": evaluated,
                "used_default": False,
            }, True
    if default:
        targets = _transition_targets(default)
        return targets, {
            "selected": targets, "label": default.get("label", "기본 경로"),
            "reason": {"default": True}, "evaluated": evaluated,
            "used_default": True,
        }, False
    return [], {"selected": [], "reason": {"no_match": True},
                "evaluated": evaluated, "used_default": False}, False


def retry_available(step: RunbookStepInstance, explicit_match: bool) -> bool:
    if explicit_match or step.outcome != "error":
        return False
    policy = json_value(step.error_policy, {})
    retry = policy.get("retry", {})
    maximum = int(retry.get("max_attempts", 0) or 0)
    return maximum > 0 and step.attempts < maximum


def recompute(db: Session, instance: RunbookInstance,
              steps: list[RunbookStepInstance],
              condition_checker: Callable[[Session, RunbookInstance,
                                           RunbookStepInstance,
                                           list[RunbookStepInstance]], bool]) -> bool:
    """Recalculate active paths. Returns True when persisted state changed."""
    changed = False
    facts = _fact_keys(steps)
    by_key = {key_for(step): step for step in steps}
    transitions = {key_for(step): json_value(step.transitions, []) for step in steps}
    graph_mode = any(transitions.values())
    static_ok = {
        key_for(step): condition_checker(db, instance, step, steps) for step in steps
    }
    incoming: dict[str, list[str]] = {key: [] for key in by_key}
    for source, rows in transitions.items():
        for transition in rows:
            for target in _transition_targets(transition):
                if target in incoming:
                    incoming[target].append(source)

    reachable = ({key for key in by_key if not incoming[key] and static_ok[key]}
                 if graph_mode else {key for key in by_key if static_ok[key]})
    decisions: dict[str, dict] = {}
    selected_incoming: dict[str, list[str]] = {key: [] for key in by_key}
    retrying: set[str] = set()
    pending = list(reachable)
    visited: set[str] = set()
    while pending:
        source_key = pending.pop(0)
        if source_key in visited:
            continue
        visited.add(source_key)
        source = by_key[source_key]
        if not resolved(source) or not transitions[source_key]:
            continue
        targets, trace, explicit = _decision(
            source, transitions[source_key], facts=facts, db=db,
            instance=instance)
        if retry_available(source, explicit):
            retrying.add(source_key)
            trace["selected"] = []
            trace["retry"] = {
                "attempt": source.attempts + 1,
                "max_attempts": int(json_value(source.error_policy, {})
                                    .get("retry", {}).get("max_attempts", 0)),
            }
            decisions[source_key] = trace
            continue
        decisions[source_key] = trace
        for target in targets:
            if target not in by_key or not static_ok[target]:
                continue
            selected_incoming[target].append(source_key)
            join = json_value(by_key[target].guidance, {}).get("join", "any")
            if join == "all":
                required = [item for item in incoming[target] if static_ok.get(item)]
                if not required or not all(item in selected_incoming[target]
                                           for item in required):
                    continue
            if target not in reachable:
                reachable.add(target)
                pending.append(target)

    for key, step in by_key.items():
        trace: list[dict] = []
        if key in decisions:
            trace.append({"kind": "branch", **decisions[key]})
        if selected_incoming[key]:
            trace.append({"kind": "activated_by",
                          "sources": selected_incoming[key]})
        if not static_ok[key]:
            activation = "excluded"
            trace.append({"kind": "excluded", "reason": "condition_not_met"})
        elif step.status in TERMINAL_STATUSES:
            activation = "completed"
        elif step.status == "blocked" or step.approval_status == "rejected":
            activation = "blocked"
        elif key in retrying:
            activation = "retry_ready"
        elif step.outcome == "error":
            activation = ("failed_handled" if decisions.get(key, {}).get("selected")
                          else "blocked")
        elif step.outcome in {"needs_review", "ambiguous"} or step.status == "suspicious":
            activation = "review_required"
        elif resolved(step) and step.outcome != "error":
            activation = "completed"
        elif key in reachable:
            if approval_required(step) and step.approval_status != "approved":
                activation = "awaiting_approval"
            elif step.status == "in_progress":
                activation = "running"
            else:
                activation = "ready"
        elif not graph_mode:
            activation = "ready"
        else:
            upstream = [by_key[item] for item in incoming[key] if item in by_key]
            activation = ("excluded" if upstream and
                          all(resolved(item) and key_for(item) not in retrying
                              for item in upstream) else "waiting")
            trace.append({
                "kind": activation,
                "reason": "another_branch_selected" if activation == "excluded"
                else "upstream_not_resolved",
                "sources": incoming[key],
            })
        encoded = json.dumps(trace, ensure_ascii=False)
        if step.activation != activation:
            step.activation = activation
            changed = True
        if step.decision_trace != encoded:
            step.decision_trace = encoded
            changed = True

    applicable = [step for step in steps if step.activation != "excluded"]
    if applicable and all(step.activation in {"completed", "failed_handled"}
                          for step in applicable):
        next_status = "completed"
    elif any(step.activation == "blocked" for step in applicable):
        next_status = "blocked"
    else:
        next_status = "active"
    if instance.status != next_status:
        instance.status = next_status
        changed = True
    return changed


def workflow_summary(steps: list[RunbookStepInstance]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for step in steps:
        counts[step.activation] = counts.get(step.activation, 0) + 1
    active = [step for step in steps if step.activation in {
        "ready", "running", "retry_ready", "review_required",
        "awaiting_approval",
    }]
    return {
        "counts": counts,
        "active_step_ids": [step.id for step in active],
        "active_node_keys": [key_for(step) for step in active],
        "blocked": counts.get("blocked", 0),
        "excluded": counts.get("excluded", 0),
    }
