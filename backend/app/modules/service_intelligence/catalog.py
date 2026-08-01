from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable

import yaml


SOURCE = Path(__file__).parents[3] / "templates" / "service_intelligence.yaml"
UNKNOWN_NAMES = {"", "unknown", "tcpwrapped", "ssl/unknown"}
LEVEL_RANK = {"generic": 0, "family": 1, "protocol": 2, "product": 3}


def _json_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, json.JSONDecodeError):
        return []


def _get(service: Any, key: str, default: Any = "") -> Any:
    return service.get(key, default) if isinstance(service, dict) else getattr(service, key, default)


@dataclass(frozen=True)
class Match:
    key: str
    level: str
    score: int
    confidence: str
    reasons: tuple[str, ...]


class ServiceIntelligenceCatalog:
    def __init__(self, source: Path = SOURCE):
        self.source = source
        self.reload()

    def reload(self) -> None:
        data = yaml.safe_load(self.source.read_text(encoding="utf-8")) or {}
        if data.get("schema_version") != 1:
            raise RuntimeError("Unsupported service intelligence schema")
        self.common_stages = data.get("common_stages", [])
        self.profiles = data.get("profiles", {})
        self.assessments = data.get("assessments", {})

    def match(self, service: Any) -> list[Match]:
        name = str(_get(service, "name", "")).strip().lower()
        product = " ".join(str(_get(service, key, "")) for key in (
            "product", "version", "extra_info"))
        protocol = str(_get(service, "protocol", "tcp")).lower()
        port = int(_get(service, "port", 0) or 0)
        cpes = [str(value).lower() for value in _json_list(_get(service, "cpe", "[]"))]
        matches: list[Match] = []
        for key, profile in self.profiles.items():
            level = profile.get("level", "protocol")
            rules = profile.get("match", {})
            reasons: list[str] = []
            score = 0
            if name and name in {str(value).lower() for value in rules.get("names", [])}:
                reasons.append(f"Nmap service name: {name}")
                score = max(score, 90)
            for pattern in rules.get("products", []):
                if product.strip() and re.search(pattern, product):
                    reasons.append(f"product evidence: {product.strip()}")
                    score = max(score, 110)
                    break
            for prefix in rules.get("cpe_prefixes", []):
                if any(value.startswith(str(prefix).lower()) for value in cpes):
                    reasons.append(f"CPE: {next(value for value in cpes if value.startswith(str(prefix).lower()))}")
                    score = max(score, 130)
                    break
            if protocol in {str(value).lower() for value in rules.get("protocols", [])}:
                if level == "generic":
                    reasons.append(f"transport: {protocol}")
                    score = max(score, 1)
            port_match = port in rules.get("ports", [])
            if port_match and score:
                reasons.append(f"supporting port: {port}/{protocol}")
            elif port_match and name in UNKNOWN_NAMES:
                reasons.append(f"port fallback: {port}/{protocol}")
                score = 25
            if not score:
                continue
            confidence = "high" if score >= 110 else "medium" if score >= 90 else "low"
            matches.append(Match(key, level, score, confidence, tuple(reasons)))
        matches.sort(key=lambda item: (LEVEL_RANK.get(item.level, 0), item.score, item.key))
        return matches

    def build(self, service: Any, related_services: Iterable[Any] = (),
              executions: Iterable[Any] = (),
              resolved_stage_ids: Iterable[str] = ()) -> dict[str, Any]:
        resolved_stage_ids = set(resolved_stage_ids)
        matches = self.match(service)
        specific = [item for item in matches if item.level != "generic"]
        selected = specific or [item for item in matches if item.level == "generic"]
        primary = selected[-1] if selected else None
        layers = []
        for item in selected:
            profile = self.profiles[item.key]
            layers.append({
                "key": item.key, "level": item.level,
                "display_name": profile.get("display_name", item.key),
                "confidence": item.confidence, "score": item.score,
                "reasons": list(item.reasons),
            })
        latest: dict[str, Any] = {}
        for row in executions:
            ref = str(_get(row, "template_id"))
            if not ref:
                continue
            previous = latest.get(ref)
            if previous is None or int(_get(row, "id", 0) or 0) > int(
                    _get(previous, "id", 0) or 0):
                latest[ref] = row
        assessments = {ref: self.assess(row) for ref, row in latest.items()}
        stages: list[dict[str, Any]] = []
        seen: set[str] = set()
        # Identity opens the workflow and evidence closes it; service-specific
        # investigation stays between those common bookends.
        identity = [row for row in self.common_stages if row.get("id") == "identity"]
        evidence = [row for row in self.common_stages if row.get("id") != "identity"]
        sources = [("common", identity)]
        sources += [(item.key, self.profiles[item.key].get("stages", [])) for item in selected]
        sources.append(("common", evidence))
        for source, rows in sources:
            for row in rows:
                ident = row["id"]
                if ident in seen:
                    continue
                seen.add(ident)
                stage = deepcopy(row)
                stage["source"] = source
                stage["commands"] = [self._command_summary(ref, assessments)
                                     for ref in stage.get("command_refs", [])]
                if any(item["completed"] for item in stage["commands"]):
                    stage["state"] = "observed"
                elif any(item.get("outcome") == "error" for item in stage["commands"]):
                    stage["state"] = "failed"
                elif any(item.get("attempted") for item in stage["commands"]):
                    stage["state"] = "review"
                else:
                    stage["state"] = "pending"
                if ident in resolved_stage_ids and stage["state"] != "failed":
                    # No command captures manual judgement (e.g. cross-referencing
                    # Exploit Research); a terminal Runbook step for this stage is
                    # the user's own resolution, so treat it as observed too.
                    stage["state"] = "observed"
                stage["completed"] = stage["state"] == "observed"
                stages.append(stage)
        profile_rows = [self.profiles[item.key] for item in selected]
        runbook_keys = list(dict.fromkeys(
            key for profile in profile_rows for key in profile.get("runbook_keys", [])))
        attack_surface = list(dict.fromkeys(
            value for profile in profile_rows for value in profile.get("attack_surface", [])))
        related = self._related(profile_rows, related_services)
        return {
            "identity": {
                "name": _get(service, "name", "unknown"),
                "product": _get(service, "product", ""),
                "version": _get(service, "version", ""),
                "extra_info": _get(service, "extra_info", ""),
                "cpe": _json_list(_get(service, "cpe", "[]")),
                "tls": bool(_get(service, "tls", False)),
                "detection_evidence": self._detection(_get(service, "detection_evidence", "{}")),
                "port": _get(service, "port", 0),
                "protocol": _get(service, "protocol", "tcp"),
            },
            "primary_profile": primary.key if primary else "generic_tcp",
            "confidence": primary.confidence if primary else "low",
            "layers": layers,
            "matches": [{"key": item["key"], "name": item["display_name"],
                         **{key: item[key] for key in ("level", "score", "reasons")}}
                        for item in layers],
            "attack_surface": attack_surface,
            "stages": stages,
            "next_stage": next((row["id"] for row in stages if row["state"] == "pending"), None),
            "runbook_keys": runbook_keys,
            "related_services": related,
            "integrations": [
                {"key": "evidence", "label": "Evidence", "purpose": "원문과 재현 가능한 근거 보존"},
                {"key": "finding", "label": "Finding", "purpose": "영향이 확인된 관찰을 후보로 승격"},
                {"key": "exploit-research", "label": "Exploit Research", "purpose": "제품·버전·구성 기반 후보 검토"},
                {"key": "reports", "label": "Report", "purpose": "확인된 사실과 제한사항을 보고서에 연결"},
            ],
        }

    def assess(self, execution: Any) -> dict[str, Any]:
        template_id = str(_get(execution, "template_id", ""))
        status = str(_get(execution, "status", ""))
        stdout = str(_get(execution, "stdout", "") or "")
        stderr = str(_get(execution, "stderr", "") or "")
        text = f"{stdout}\n{stderr}"
        if status != "completed":
            return {
                "execution_id": _get(execution, "id", None),
                "template_id": template_id,
                "outcome": "error" if status in {"failed", "error", "interrupted"} else "needs_review",
                "summary": stderr.strip() or f"Execution status: {status}",
                "facts": [], "next": [], "raw_preserved": True,
                "execution_status": status,
                "error_type": ("technical_failure" if status in {
                    "failed", "error", "interrupted"} else "incomplete"),
            }
        definition = self.assessments.get(template_id, {})
        outcome, summary, next_steps = "needs_review", (
            "명령은 종료됐지만 확인된 정보는 사용자가 판정해야 합니다."), []
        for rule in definition.get("rules", []):
            if re.search(rule["pattern"], text):
                outcome = rule.get("outcome", outcome)
                summary = rule.get("summary", summary)
                next_steps = rule.get("next", [])
                break
        facts: list[dict[str, Any]] = []
        for extractor in definition.get("extractors", []):
            facts.extend(EXTRACTORS.get(extractor, lambda _: [])(text))
        return {
            "execution_id": _get(execution, "id", None),
            "template_id": template_id, "outcome": outcome,
            "summary": summary, "facts": facts, "next": next_steps,
            "raw_preserved": True, "execution_status": status,
            "error_type": None,
        }

    @staticmethod
    def _command_summary(ref: str, assessments: dict[str, dict]) -> dict[str, Any]:
        from ...templates import catalog as command_catalog
        item = command_catalog.items.get(ref, {})
        assessment = assessments.get(ref)
        outcome = assessment.get("outcome", "") if assessment else ""
        completed = outcome in {
            "confirmed", "not_found", "access_denied", "authentication_required",
            "partial", "not_applicable",
        }
        return {
            "id": ref, "name": item.get("name", ref),
            "description": item.get("description", ""),
            "risk": item.get("risk", "unknown"),
            "execution_mode": item.get("execution_mode", "manual"),
            "available": bool(item), "completed": completed,
            "attempted": assessment is not None, "outcome": outcome,
            "summary": assessment.get("summary", "") if assessment else "",
            "facts": assessment.get("facts", []) if assessment else [],
            "execution_id": assessment.get("execution_id") if assessment else None,
        }

    @staticmethod
    def _detection(value: Any) -> dict:
        if isinstance(value, dict):
            return value
        try:
            parsed = json.loads(value or "{}")
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _related(profiles: list[dict], services: Iterable[Any]) -> list[dict]:
        rows, seen = [], set()
        available = list(services)
        for profile in profiles:
            for relation in profile.get("related", []):
                names = {str(value).lower() for value in relation.get("names", [])}
                for service in available:
                    if str(_get(service, "name", "")).lower() not in names:
                        continue
                    ident = _get(service, "id", None)
                    if ident in seen:
                        continue
                    seen.add(ident)
                    rows.append({
                        "service_id": ident, "name": _get(service, "name", ""),
                        "port": _get(service, "port", 0), "protocol": _get(service, "protocol", "tcp"),
                        "label": relation.get("label", "Related service"),
                        "reason": relation.get("reason", ""),
                        "merge_with_current": False,
                    })
        return rows


def _unique_facts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result, seen = [], set()
    for row in rows:
        marker = (row.get("key"), str(row.get("value")))
        if marker in seen:
            continue
        seen.add(marker)
        result.append(row)
    return result


def extract_smb_shares(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\S+)\s+(Disk|IPC|Printer)\s*(.*)$", line, re.I)
        if match and match.group(1).lower() != "sharename":
            rows.append({"key": "smb.share", "label": "SMB share",
                         "value": {"name": match.group(1), "type": match.group(2),
                                   "comment": match.group(3).strip()}})
    return rows


def extract_http_headers(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        if re.match(r"^HTTP/\S+\s+\d{3}", line, re.I):
            rows.append({"key": "http.status", "label": "HTTP status", "value": line.strip()})
        elif ":" in line:
            key, value = line.split(":", 1)
            if key.lower() in {"server", "location", "www-authenticate", "set-cookie", "allow", "x-powered-by"}:
                rows.append({"key": f"http.header.{key.lower()}", "label": key.strip(),
                             "value": value.strip()})
    return _unique_facts(rows)


def extract_rpc_uuids(text: str) -> list[dict[str, Any]]:
    values = re.findall(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", text)
    return [{"key": "rpc.uuid", "label": "RPC interface UUID", "value": value.lower()}
            for value in dict.fromkeys(values)]


def _rpc_json_lines(text: str, prefix: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        if not line.startswith(prefix + " "):
            continue
        try:
            value = json.loads(line[len(prefix) + 1:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def extract_rpc_endpoints(text: str) -> list[dict[str, Any]]:
    return [{"key": "rpc.endpoint", "label": "RPC endpoint", "value": row}
            for row in _rpc_json_lines(text, "RPC_ENDPOINT")]


def extract_rpc_bind_results(text: str) -> list[dict[str, Any]]:
    return [{"key": "rpc.bind", "label": "RPC bind result", "value": row}
            for row in _rpc_json_lines(text, "RPC_BIND_RESULT")]


def extract_redis_info(text: str) -> list[dict[str, Any]]:
    rows = []
    for key in ("redis_version", "redis_mode", "role", "os"):
        match = re.search(rf"(?im)^{key}:([^\r\n]+)", text)
        if match:
            rows.append({"key": f"redis.{key}", "label": key.replace("_", " ").title(),
                         "value": match.group(1).strip()})
    return rows


def extract_nmap_service(text: str) -> list[dict[str, Any]]:
    rows = []
    for match in re.finditer(r"(?im)^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$", text):
        rows.append({"key": "service.observation", "label": "Nmap service observation",
                     "value": {"port": int(match.group(1)), "protocol": match.group(2),
                               "name": match.group(3), "product": (match.group(4) or "").strip()}})
    return rows


def extract_smb_security(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        if re.search(r"(?i)SMBv1|dialect|message signing", line):
            rows.append({"key": "smb.security", "label": "SMB security setting", "value": line.strip()})
    return _unique_facts(rows)


EXTRACTORS = {
    "smb_shares": extract_smb_shares,
    "http_headers": extract_http_headers,
    "rpc_uuids": extract_rpc_uuids,
    "rpc_endpoints": extract_rpc_endpoints,
    "rpc_bind_results": extract_rpc_bind_results,
    "redis_info": extract_redis_info,
    "nmap_service": extract_nmap_service,
    "smb_security": extract_smb_security,
}


catalog = ServiceIntelligenceCatalog()
