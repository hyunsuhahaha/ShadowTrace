from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path
import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...database import get_db
from ...models import HttpExchange, HttpRequest, Project, Service, Target
from ...schemas import HttpExchangeOut, HttpRequestIn, HttpRequestOut, HttpSendIn
from ...time import utcnow
from ..scan_center.service import _safe

router = APIRouter(prefix="/api/web", tags=["Web Testing"])
MAX_RESPONSE = 10 * 1024 * 1024


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def public_exchange(row: HttpExchange) -> dict:
    return {key: getattr(row, key) for key in (
        "id", "request_id", "status_code", "duration_ms", "size",
        "request_snapshot", "response_headers", "response_cookies",
        "body_path", "sha256", "error", "created_at")}


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


async def send_once(db: Session, row: HttpRequest,
                    variables: dict[str, str]) -> HttpExchange:
    target = need(db, Target, row.target_id)
    project = need(db, Project, row.project_id)
    url = substitute(row.url, variables)
    query = {key: substitute(value, variables)
             for key, value in json.loads(row.query).items()}
    headers = {key: substitute(value, variables)
               for key, value in json.loads(row.headers).items()}
    cookies = {key: substitute(value, variables)
               for key, value in json.loads(row.cookies).items()}
    body = substitute(row.body, variables)
    snapshot = json.dumps({"method": row.method, "url": url, "query": query,
                           "headers": headers, "cookies": cookies,
                           "body": body, "body_mode": row.body_mode},
                          ensure_ascii=False)
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
        if len(content) > MAX_RESPONSE:
            raise ValueError("Response exceeded the 10 MiB preservation limit")
        folder = (WORKSPACE_DIR / "projects" / _safe(project.name) / "targets" /
                  _safe(target.ip) / "http" / str(row.id))
        folder.mkdir(parents=True, exist_ok=True)
        db.add(exchange); db.flush()
        path = folder / f"response-{exchange.id}.bin"
        path.write_bytes(content)
        exchange.status_code = response.status_code
        exchange.duration_ms = round((time.perf_counter() - started) * 1000)
        exchange.size = len(content)
        exchange.response_headers = json.dumps(dict(response.headers), ensure_ascii=False)
        exchange.response_cookies = json.dumps(dict(response.cookies), ensure_ascii=False)
        exchange.response_body = content
        exchange.body_path = str(path)
        exchange.sha256 = hashlib.sha256(content).hexdigest()
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


@router.get("/requests/{ident}/exchanges", response_model=list[HttpExchangeOut])
def exchanges(ident: int, db: Session = Depends(get_db)):
    need(db, HttpRequest, ident)
    rows = db.scalars(select(HttpExchange).where(
        HttpExchange.request_id == ident).order_by(HttpExchange.id.desc())).all()
    return [public_exchange(row) for row in rows]

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
