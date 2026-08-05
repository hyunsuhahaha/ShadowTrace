from __future__ import annotations
import base64
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import HttpExchange, HttpRequest, Project, Target
from ...schemas import (
    HttpExchangeOut, HttpRequestOut, ProxyCaptureIn, ProxyCaptureOut, ProxyStartIn,
)
from ...time import utcnow
from ..web_testing.router import (
    cloud_fingerprint_for_exchange, need, persist_exchange_body, public_exchange,
)
from .manager import CONFDIR, manager

router = APIRouter(prefix="/api/web/proxy", tags=["Web Proxy"])
CAPTURE_TAG = "proxy-capture"


@router.post("/start")
async def start_proxy(body: ProxyStartIn):
    try:
        return await manager.start(body.project_id, body.target_id, body.port)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))


@router.post("/stop")
async def stop_proxy():
    return await manager.stop()


@router.get("/status")
def proxy_status():
    return manager.status()


@router.get("/ca-cert")
def download_ca_cert():
    path = CONFDIR / "mitmproxy-ca-cert.pem"
    if not path.is_file():
        raise HTTPException(404, "프록시를 먼저 한 번 시작하면 인증서가 생성됩니다.")
    return FileResponse(path, filename="mitmproxy-ca-cert.pem",
                        media_type="application/x-x509-ca-cert")


@router.get("/captures", response_model=list[ProxyCaptureOut])
def captures(target_id: int, db: Session = Depends(get_db)):
    rows = db.scalars(select(HttpRequest).where(
        HttpRequest.target_id == target_id).order_by(HttpRequest.id.desc())).all()
    captured = [row for row in rows if CAPTURE_TAG in json.loads(row.tags or "[]")]

    # One query for every captured request's exchanges rather than one
    # query per row, then keep the latest (highest id) per request in
    # Python — the per-target capture count here is small (a pentest/CTF
    # session, not production traffic), so this stays simple.
    request_ids = [row.id for row in captured]
    latest_exchange: dict[int, HttpExchange] = {}
    if request_ids:
        for exchange in db.scalars(select(HttpExchange).where(
                HttpExchange.request_id.in_(request_ids))).all():
            current = latest_exchange.get(exchange.request_id)
            if current is None or exchange.id > current.id:
                latest_exchange[exchange.request_id] = exchange

    results = []
    for row in captured:
        exchange = latest_exchange.get(row.id)
        fingerprint = cloud_fingerprint_for_exchange(exchange) if exchange else None
        if fingerprint and fingerprint.get("provider") == "unknown":
            fingerprint = None
        results.append(ProxyCaptureOut(
            **HttpRequestOut.model_validate(row).model_dump(),
            cloud_fingerprint=fingerprint, has_response=exchange is not None,
        ))
    return results


@router.post("/capture", response_model=HttpExchangeOut, status_code=201)
def capture(body: ProxyCaptureIn, db: Session = Depends(get_db)):
    target = need(db, Target, body.target_id)
    project = need(db, Project, body.project_id)
    existing = db.scalars(select(HttpRequest).where(
        HttpRequest.target_id == body.target_id,
        HttpRequest.method == body.method,
        HttpRequest.url == body.url,
    )).first()
    row = existing if existing and CAPTURE_TAG in json.loads(existing.tags or "[]") else None
    request_body = base64.b64decode(body.body) if body.body else b""
    if not row:
        row = HttpRequest(
            project_id=body.project_id, target_id=body.target_id,
            name=f"{body.method} {body.url}"[:160], folder="Proxy Capture",
            tags=json.dumps([CAPTURE_TAG]), method=body.method, url=body.url,
            query="{}", headers=json.dumps(body.headers, ensure_ascii=False),
            cookies=json.dumps(body.cookies, ensure_ascii=False),
            body=request_body.decode(errors="replace"), body_mode="raw")
        db.add(row); db.flush()
    else:
        row.headers = json.dumps(body.headers, ensure_ascii=False)
        row.cookies = json.dumps(body.cookies, ensure_ascii=False)
        row.body = request_body.decode(errors="replace")
        row.updated_at = utcnow()

    safe_cookies = {key: "••••••" for key in body.cookies}
    snapshot = json.dumps({"method": body.method, "url": body.url,
                           "headers": body.headers, "cookies": safe_cookies,
                           "body_mode": "raw"}, ensure_ascii=False)
    exchange = HttpExchange(request_id=row.id, request_snapshot=snapshot,
                            status_code=body.status_code, duration_ms=body.duration_ms,
                            response_headers=json.dumps(body.response_headers, ensure_ascii=False),
                            response_cookies=json.dumps(body.response_cookies, ensure_ascii=False))
    content = base64.b64decode(body.response_body) if body.response_body else b""
    try:
        persist_exchange_body(db, project, target, row, exchange, content)
    except ValueError as exc:
        db.add(exchange); db.flush()
        exchange.error = str(exc)
    db.commit(); db.refresh(exchange)
    return public_exchange(exchange)
