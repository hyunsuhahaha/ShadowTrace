import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import HttpExchange, HttpRequest, Project, Target
import pytest
from fastapi import HTTPException
from app.modules.web_testing.router import (
    payload_combinations, require_private_destination, review_exchange,
    send_once, substitute,
)
from app.schemas import ExchangeReviewIn, IntruderRunIn


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_variable_substitution_is_explicit():
    assert substitute("/users/{{id}}?literal={{missing}}",
                      {"id": "42"}) == "/users/42?literal={{missing}}"


def test_intruder_combinations_and_limit():
    body = IntruderRunIn(
        run_id="test-run-1",
        attack_type="cluster_bomb",
        positions=[
            {"name": "user", "candidates": ["a", "b"]},
            {"name": "pin", "candidates": ["1", "2"]},
        ],
        max_requests=4, confirmed=True,
    )
    assert payload_combinations(body) == [
        {"user": "a", "pin": "1"}, {"user": "a", "pin": "2"},
        {"user": "b", "pin": "1"}, {"user": "b", "pin": "2"},
    ]
    body.max_requests = 3
    with pytest.raises(HTTPException):
        payload_combinations(body)


def test_review_exchange_persists_and_defaults_to_pending():
    db = database()
    project = Project(name="Web Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    request = HttpRequest(
        project_id=project.id, target_id=target.id, name="Request",
        method="GET", url="http://10.10.10.10/")
    db.add(request); db.flush()
    exchange = HttpExchange(request_id=request.id, request_snapshot="GET /")
    db.add(exchange); db.commit()
    assert exchange.review_status == "pending"

    updated = review_exchange(
        exchange.id, ExchangeReviewIn(review_status="confirmed"), db)

    assert updated["review_status"] == "confirmed"
    db.expire_all()
    assert db.get(HttpExchange, exchange.id).review_status == "confirmed"


def test_destination_policy_rejects_public_and_dns_names():
    require_private_destination("http://127.0.0.1/")
    require_private_destination("http://10.10.10.10/")
    with pytest.raises(HTTPException):
        require_private_destination("https://example.com/")
    with pytest.raises(HTTPException):
        require_private_destination("https://8.8.8.8/")


def test_user_authored_request_preserves_raw_response(tmp_path, monkeypatch):
    import app.modules.web_testing.router as router

    class Response:
        status_code = 200
        content = b'{"ok":true}'
        headers = {"content-type": "application/json"}
        cookies = {"session": "observed"}

    class Client:
        def __init__(self, **kwargs):
            self.options = kwargs
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def request(self, method, url, **kwargs):
            assert method == "GET"
            assert url == "http://10.10.10.10/items/7"
            assert kwargs["headers"]["X-Test"] == "7"
            return Response()

    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(router.httpx, "AsyncClient", Client)
    db = database()
    project = Project(name="Web Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    request = HttpRequest(
        project_id=project.id, target_id=target.id, name="Observed request",
        method="GET", url="http://10.10.10.10/items/{{id}}",
        headers='{"X-Test":"{{id}}","Authorization":"Bearer secret"}',
        cookies='{"session":"secret"}')
    db.add(request); db.commit()
    exchange = asyncio.run(send_once(db, request, {"id": "7"}))
    assert exchange.status_code == 200
    assert exchange.response_body == b'{"ok":true}'
    assert exchange.sha256
    assert "Bearer secret" not in exchange.request_snapshot
    assert '"session": "••••••"' in exchange.request_snapshot
