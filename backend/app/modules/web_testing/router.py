from __future__ import annotations
import hashlib
import json
import time
import asyncio
import base64
import ipaddress
import re
from itertools import product
from urllib.parse import quote, urlparse
from pathlib import Path
import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...cloud_storage_probe import classify_provider
from ...database import get_db
from ...models import HttpExchange, HttpRequest, Project, Service, Target
from ...schemas import (
    ExchangeReviewIn, HttpExchangeOut, HttpRequestIn, HttpRequestOut,
    HttpSendIn, IntruderRunIn,
)
from ...time import utcnow
from ..scan_center.service import _safe

router = APIRouter(prefix="/api/web", tags=["Web Testing"])
MAX_RESPONSE = 10 * 1024 * 1024
MAX_INTRUDER_REQUESTS = 100
MAX_FINGERPRINT_BODY = 65536
intruder_runs: dict[str, dict] = {}


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def cloud_fingerprint_for_exchange(exchange: HttpExchange) -> dict | None:
    # No status_code means the request errored out before a response came
    # back (DNS failure, connection refused, etc.) — nothing to classify.
    if exchange.status_code is None:
        return None
    headers = json.loads(exchange.response_headers or "{}")
    body = (exchange.response_body or b"")[:MAX_FINGERPRINT_BODY].decode(
        "utf-8", "replace")
    return classify_provider(headers, body)


def public_exchange(row: HttpExchange) -> dict:
    return {
        **{key: getattr(row, key) for key in (
            "id", "request_id", "status_code", "duration_ms", "size",
            "request_snapshot", "response_headers", "response_cookies",
            "body_path", "sha256", "error", "review_status", "created_at")},
        "cloud_fingerprint": cloud_fingerprint_for_exchange(row),
    }


@router.get("/requests", response_model=list[HttpRequestOut])
def requests(target_id: int | None = None, db: Session = Depends(get_db)):
    statement = select(HttpRequest).order_by(HttpRequest.id.desc())
    if target_id:
        statement = statement.where(HttpRequest.target_id == target_id)
    return db.scalars(statement.limit(500)).all()


@router.post("/requests", response_model=HttpRequestOut, status_code=201)
def create_request(body: HttpRequestIn, db: Session = Depends(get_db)):
    target = need(db, Target, body.target_id)
    if target.project_id != body.project_id:
        raise HTTPException(400, "Target does not belong to the project")
    if body.service_id:
        service = need(db, Service, body.service_id)
        if service.target_id != target.id:
            raise HTTPException(400, "Service does not belong to the target")
    values = body.model_dump()
    values["url"] = str(values["url"])
    for key in ("tags", "query", "headers", "cookies"):
        values[key] = json.dumps(values[key], ensure_ascii=False)
    row = HttpRequest(**values)
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.put("/requests/{ident}", response_model=HttpRequestOut)
def update_request(ident: int, body: HttpRequestIn,
                   db: Session = Depends(get_db)):
    row = need(db, HttpRequest, ident)
    values = body.model_dump()
    values["url"] = str(values["url"])
    for key in ("tags", "query", "headers", "cookies"):
        values[key] = json.dumps(values[key], ensure_ascii=False)
    for key, value in values.items():
        setattr(row, key, value)
    row.updated_at = utcnow()
    db.commit(); db.refresh(row)
    return row


@router.post("/requests/{ident}/duplicate", response_model=HttpRequestOut,
             status_code=201)
def duplicate_request(ident: int, db: Session = Depends(get_db)):
    source = need(db, HttpRequest, ident)
    values = {column.name: getattr(source, column.name)
              for column in HttpRequest.__table__.columns
              if column.name not in ("id", "created_at", "updated_at")}
    values["name"] = f"{source.name} copy"[:160]
    row = HttpRequest(**values)
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.delete("/requests/{ident}", status_code=204)
def delete_request(ident: int, db: Session = Depends(get_db)):
    row = need(db, HttpRequest, ident)
    for exchange in db.scalars(select(HttpExchange).where(
            HttpExchange.request_id == ident)).all():
        if exchange.body_path:
            Path(exchange.body_path).unlink(missing_ok=True)
        db.delete(exchange)
    db.delete(row); db.commit()


def substitute(value: str, variables: dict[str, str]) -> str:
    for key, replacement in variables.items():
        value = value.replace("{{" + key + "}}", replacement)
    return value


def require_private_destination(url: str) -> None:
    hostname = urlparse(url).hostname
    if hostname == "localhost":
        return
    try:
        address = ipaddress.ip_address(hostname)
    except (ValueError, TypeError):
        raise HTTPException(
            403, "DNS 재바인딩 방지를 위해 localhost 또는 사설 IP 주소를 직접 입력하세요.")
    if not (address.is_private or address.is_loopback):
        raise HTTPException(403, "기본 안전 정책은 localhost와 사설 IP 대상만 허용합니다.")


def masked_snapshot(row: HttpRequest, url: str, query: dict[str, str],
                    headers: dict[str, str], cookies: dict[str, str],
                    body: str) -> str:
    sensitive = re.compile(r"(authorization|cookie|password|passwd|secret|token)", re.I)
    safe_headers = {key: ("••••••" if sensitive.search(key) else value)
                    for key, value in headers.items()}
    safe_cookies = {key: "••••••" for key in cookies}
    safe_query = {key: ("••••••" if sensitive.search(key) else value)
                  for key, value in query.items()}
    safe_body = body
    if row.body_mode == "json" and body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                safe_body = json.dumps({
                    key: ("••••••" if sensitive.search(key) else value)
                    for key, value in parsed.items()
                }, ensure_ascii=False)
        except json.JSONDecodeError:
            pass
    return json.dumps({"method": row.method, "url": url, "query": safe_query,
                       "headers": safe_headers, "cookies": safe_cookies,
                       "body": safe_body, "body_mode": row.body_mode},
                      ensure_ascii=False)


def persist_exchange_body(db: Session, project: Project, target: Target,
                          row: HttpRequest, exchange: HttpExchange,
                          content: bytes) -> None:
    if len(content) > MAX_RESPONSE:
        raise ValueError("Response exceeded the 10 MiB preservation limit")
    folder = (WORKSPACE_DIR / "projects" / _safe(project.name) / "targets" /
              _safe(target.ip) / "http" / str(row.id))
    folder.mkdir(parents=True, exist_ok=True)
    db.add(exchange); db.flush()
    path = folder / f"response-{exchange.id}.bin"
    path.write_bytes(content)
    exchange.size = len(content)
    exchange.response_body = content
    exchange.body_path = str(path)
    exchange.sha256 = hashlib.sha256(content).hexdigest()


async def send_once(db: Session, row: HttpRequest,
                    variables: dict[str, str]) -> HttpExchange:
    target = need(db, Target, row.target_id)
    project = need(db, Project, row.project_id)
    url = substitute(row.url, variables)
    require_private_destination(url)
    query = {key: substitute(value, variables)
             for key, value in json.loads(row.query).items()}
    headers = {key: substitute(value, variables)
               for key, value in json.loads(row.headers).items()}
    cookies = {key: substitute(value, variables)
               for key, value in json.loads(row.cookies).items()}
    body = substitute(row.body, variables)
    snapshot = masked_snapshot(row, url, query, headers, cookies, body)
    exchange = HttpExchange(request_id=row.id, request_snapshot=snapshot)
    started = time.perf_counter()
    try:
        kwargs = {"params": query, "headers": headers, "cookies": cookies}
        if row.body_mode == "json" and body:
            kwargs["json"] = json.loads(body)
        elif row.body_mode == "form" and body:
            kwargs["data"] = dict(item.split("=", 1) for item in body.split("&"))
        elif body:
            kwargs["content"] = body.encode()
        async with httpx.AsyncClient(
            verify=row.tls_verify, proxy=row.proxy or None,
            timeout=row.timeout, follow_redirects=row.follow_redirects,
            max_redirects=10) as client:
            response = await client.request(row.method, url, **kwargs)
        content = response.content
        persist_exchange_body(db, project, target, row, exchange, content)
        exchange.status_code = response.status_code
        exchange.duration_ms = round((time.perf_counter() - started) * 1000)
        exchange.response_headers = json.dumps(dict(response.headers), ensure_ascii=False)
        exchange.response_cookies = json.dumps(dict(response.cookies), ensure_ascii=False)
    except Exception as exc:
        exchange.duration_ms = round((time.perf_counter() - started) * 1000)
        exchange.error = str(exc)
    db.add(exchange); db.commit(); db.refresh(exchange)
    return exchange


@router.post("/requests/{ident}/send", response_model=list[HttpExchangeOut])
async def send_request(ident: int, body: HttpSendIn,
                       db: Session = Depends(get_db)):
    row = need(db, HttpRequest, ident)
    if not body.confirmed:
        raise HTTPException(400, "Scope confirmation is required")
    return [await send_once(db, row, body.variables) for _ in range(body.repeat)]


def process_payload(value: str, rules) -> str:
    value = value.strip()
    for rule in rules:
        if rule.type == "prefix":
            value = rule.value + value
        elif rule.type == "suffix":
            value += rule.value
        elif rule.type == "lower":
            value = value.lower()
        elif rule.type == "upper":
            value = value.upper()
        elif rule.type == "url_encode":
            value = quote(value, safe="")
        elif rule.type == "base64":
            value = base64.b64encode(value.encode()).decode()
        elif rule.type == "replace":
            value = value.replace(rule.value, rule.replacement)
        else:
            try:
                value = re.sub(rule.value, rule.replacement, value)
            except re.error as exc:
                raise HTTPException(422, f"잘못된 정규식 처리 규칙: {exc}")
    return value


def payload_combinations(body: IntruderRunIn) -> list[dict[str, str]]:
    sets = [(position.name,
             [process_payload(value, position.rules)
              for value in position.candidates])
            for position in body.positions]
    base = {name: "{{" + name + "}}" for name, _ in sets}
    if body.attack_type == "sniper":
        combinations = [{**base, name: value}
                        for name, values in sets for value in values]
    elif body.attack_type == "battering_ram":
        combinations = [{name: value for name, _ in sets}
                        for value in sets[0][1]]
    elif body.attack_type == "pitchfork":
        combinations = [dict(zip((name for name, _ in sets), values))
                        for values in zip(*(values for _, values in sets))]
    else:
        combinations = [dict(zip((name for name, _ in sets), values))
                        for values in product(*(values for _, values in sets))]
    if len(combinations) > min(body.max_requests, MAX_INTRUDER_REQUESTS):
        raise HTTPException(
            400, f"예상 요청 {len(combinations)}개가 승인 상한 "
                 f"{min(body.max_requests, MAX_INTRUDER_REQUESTS)}개를 초과합니다.")
    return combinations


async def controlled_wait(state: dict, delay_ms: int) -> bool:
    remaining = delay_ms / 1000
    while remaining > 0:
        while state["status"] == "paused":
            await asyncio.sleep(.1)
        if state["status"] == "stopped":
            return False
        interval = min(.1, remaining)
        await asyncio.sleep(interval)
        remaining -= interval
    return True


@router.post("/requests/{ident}/intruder")
async def run_intruder(ident: int, body: IntruderRunIn,
                       db: Session = Depends(get_db)):
    row = need(db, HttpRequest, ident)
    if not body.confirmed:
        raise HTTPException(400, "최종 요청과 허가 범위의 명시적 승인이 필요합니다.")
    combinations = payload_combinations(body)
    markers = set(re.findall(r"\{\{([A-Za-z][A-Za-z0-9_]*)\}\}",
                             " ".join((row.url, row.query, row.headers,
                                       row.cookies, row.body))))
    names = {position.name for position in body.positions}
    if not names <= markers:
        raise HTTPException(400, "모든 변형 위치는 요청에 {{name}} 마커로 존재해야 합니다.")
    if body.run_id in intruder_runs:
        raise HTTPException(409, "같은 실행 ID가 이미 사용 중입니다.")
    state = {"status": "running", "completed": 0, "total": len(combinations)}
    intruder_runs[body.run_id] = state
    results = []
    try:
        for index, variables in enumerate(combinations):
            if not await controlled_wait(state, body.delay_ms if index else 0):
                break
            exchange = await send_once(db, row, variables)
            for _ in range(body.retry_count):
                if not exchange.error:
                    break
                exchange = await send_once(db, row, variables)
            text = exchange.response_body.decode(errors="replace")
            regex_matches = []
            for pattern in body.grep_regexes:
                try:
                    regex_matches.append(bool(re.search(pattern, text)))
                except re.error as exc:
                    raise HTTPException(422, f"잘못된 응답 정규식: {exc}")
            headers = json.loads(exchange.response_headers or "{}")
            results.append({
                "exchange_id": exchange.id,
                "position_values": variables,
                "status_code": exchange.status_code,
                "response_length": exchange.size,
                "word_count": len(text.split()),
                "line_count": len(text.splitlines()),
                "duration_ms": exchange.duration_ms,
                "redirect": headers.get("location", ""),
                "content_type": headers.get("content-type", ""),
                "string_matches": [value in text for value in body.grep_strings],
                "regex_matches": regex_matches,
                "review_status": exchange.review_status,
                "error": exchange.error,
            })
            state["completed"] = len(results)
            if (exchange.status_code in body.stop_status_codes or
                    (body.stop_string and body.stop_string in text)):
                state["status"] = "stopped"
                state["reason"] = "설정한 응답 중단 조건"
                break
        if state["status"] not in ("stopped",):
            state["status"] = "completed"
        return {"request_count": len(results), "status": state["status"],
                "stop_reason": state.get("reason", ""), "results": results}
    finally:
        state["finished"] = True


@router.get("/intruder/{run_id}")
def intruder_status(run_id: str):
    state = intruder_runs.get(run_id)
    if not state:
        raise HTTPException(404, "실행을 찾을 수 없습니다.")
    return state


@router.post("/intruder/{run_id}/{action}")
def control_intruder(run_id: str, action: str):
    state = intruder_runs.get(run_id)
    if not state:
        raise HTTPException(404, "실행을 찾을 수 없습니다.")
    if action not in ("pause", "resume", "stop"):
        raise HTTPException(400, "지원하지 않는 실행 제어입니다.")
    if state["status"] in ("completed", "stopped"):
        return state
    state["status"] = {"pause": "paused", "resume": "running",
                       "stop": "stopped"}[action]
    return state


@router.get("/requests/{ident}/exchanges", response_model=list[HttpExchangeOut])
def exchanges(ident: int, db: Session = Depends(get_db)):
    need(db, HttpRequest, ident)
    rows = db.scalars(select(HttpExchange).where(
        HttpExchange.request_id == ident).order_by(HttpExchange.id.desc())).all()
    return [public_exchange(row) for row in rows]

@router.patch("/exchanges/{ident}/review", response_model=HttpExchangeOut)
def review_exchange(ident: int, body: ExchangeReviewIn, db: Session = Depends(get_db)):
    row = need(db, HttpExchange, ident)
    row.review_status = body.review_status
    db.commit()
    db.refresh(row)
    return public_exchange(row)


@router.get("/exchanges/{base_id}/compare/{current_id}")
def compare_exchanges(base_id: int, current_id: int,
                      db: Session = Depends(get_db)):
    base = need(db, HttpExchange, base_id)
    current = need(db, HttpExchange, current_id)
    if base.request_id != current.request_id:
        raise HTTPException(400, "Responses must belong to the same saved request")
    changes = {}
    for field in ("status_code", "size", "response_headers",
                  "response_cookies", "sha256"):
        before, after = getattr(base, field), getattr(current, field)
        if before != after:
            changes[field] = {"before": before, "after": after}
    return {"base_id": base_id, "current_id": current_id,
            "changed": bool(changes), "changes": changes}


@router.get("/exchanges/{ident}/body")
def exchange_body(ident: int, download: bool = False,
                  db: Session = Depends(get_db)):
    row = need(db, HttpExchange, ident)
    if download and row.body_path:
        path = Path(row.body_path)
        if not path.is_file():
            raise HTTPException(410, "Response body is no longer available")
        return FileResponse(path, filename=f"response-{row.id}.bin",
                            media_type="application/octet-stream")
    return Response(row.response_body, media_type="application/octet-stream")
