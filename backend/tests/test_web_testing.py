import asyncio
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import HttpExchange, HttpRequest, Project, Target
import pytest
from fastapi import HTTPException
from app.modules.web_testing.router import (
    cloud_fingerprint_for_exchange, payload_combinations, public_exchange,
    require_private_destination, review_exchange, send_once, substitute,
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


def test_cloud_fingerprint_is_none_when_the_request_never_got_a_response():
    exchange = HttpExchange(request_id=1, request_snapshot="GET /", status_code=None)
    assert cloud_fingerprint_for_exchange(exchange) is None


def test_cloud_fingerprint_classifies_a_stored_exchange():
    exchange = HttpExchange(
        request_id=1, request_snapshot="GET /", status_code=403,
        response_headers=json.dumps({"Server": "AmazonS3", "x-amz-request-id": "R1"}),
        response_body=b"<Error><Code>AccessDenied</Code></Error>",
    )
    result = cloud_fingerprint_for_exchange(exchange)
    assert result["provider"] == "aws-s3"
    assert result["meaning"] is not None


def test_public_exchange_carries_the_same_fingerprint_used_by_review():
    # review_exchange() returns public_exchange(row), so this is the same
    # code path a client hits after PATCHing a review status — it should
    # reflect the response, not just echo back stored review fields.
    db = database()
    project = Project(name="Web Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    request = HttpRequest(
        project_id=project.id, target_id=target.id, name="Request",
        method="GET", url="http://10.10.10.10/")
    db.add(request); db.flush()
    exchange = HttpExchange(
        request_id=request.id, request_snapshot="GET /", status_code=403,
        response_headers=json.dumps({"Server": "AmazonS3", "x-amz-request-id": "R1"}),
        response_body=b"<Error><Code>AccessDenied</Code></Error>")
    db.add(exchange); db.commit()

    assert public_exchange(exchange)["cloud_fingerprint"]["provider"] == "aws-s3"

    updated = review_exchange(
        exchange.id, ExchangeReviewIn(review_status="confirmed"), db)
    assert updated["cloud_fingerprint"]["provider"] == "aws-s3"


def test_destination_policy_rejects_public_and_dns_names():
    require_private_destination("http://127.0.0.1/")
    require_private_destination("http://10.10.10.10/")
    with pytest.raises(HTTPException):
        require_private_destination("https://example.com/")
    with pytest.raises(HTTPException):
        require_private_destination("https://8.8.8.8/")


def test_destination_policy_allows_a_vhost_hostname_that_resolves_privately(monkeypatch):
    # This app's own hostname-confirmation feature exists so a vhost-routed
    # target (pinned to a private IP via /etc/hosts) can be addressed by
    # name instead of bare IP — rejecting every non-literal-IP hostname
    # outright would defeat that for exactly the requests it's meant for.
    import app.modules.web_testing.router as router
    monkeypatch.setattr(router.socket, "gethostbyname",
        lambda name: "10.129.95.234" if name == "unika.htb" else (_ for _ in ()).throw(
            router.socket.gaierror("unknown host")))

    require_private_destination("http://unika.htb/index.php?page=test")

    with pytest.raises(HTTPException):
        require_private_destination("http://not-in-hosts.example/")


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


def test_a_query_string_typed_directly_into_the_url_survives_an_empty_query_json_panel(
        tmp_path, monkeypatch):
    # httpx's params= replaces the URL's own query string outright rather
    # than merging with it, so passing params={} (an empty/untouched Query
    # JSON panel — the normal case when someone just types the whole URL,
    # query string included, into the URL field) used to silently strip it
    # before the request ever left the box.
    import app.modules.web_testing.router as router

    class Response:
        status_code = 200
        content = b"ok"
        headers = {}
        cookies = {}

    sent_urls = []

    class Client:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def request(self, method, url, **kwargs):
            sent_urls.append(url)
            assert "params" not in kwargs
            return Response()

    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(router.httpx, "AsyncClient", Client)
    db = database()
    project = Project(name="Web Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    request = HttpRequest(
        project_id=project.id, target_id=target.id, name="Typed query string",
        method="GET", url="http://10.10.10.10/index.php?page=\\\\10.10.10.5\\test")
    db.add(request); db.commit()

    asyncio.run(send_once(db, request, {}))

    assert sent_urls == ["http://10.10.10.10/index.php?page=\\\\10.10.10.5\\test"]
