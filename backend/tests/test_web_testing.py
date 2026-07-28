import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import HttpRequest, Project, Target
from app.modules.web_testing.router import send_once, substitute


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_variable_substitution_is_explicit():
    assert substitute("/users/{{id}}?literal={{missing}}",
                      {"id": "42"}) == "/users/42?literal={{missing}}"


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
        headers='{"X-Test":"{{id}}"}')
    db.add(request); db.commit()
    exchange = asyncio.run(send_once(db, request, {"id": "7"}))
    assert exchange.status_code == 200
    assert exchange.response_body == b'{"ok":true}'
    assert exchange.sha256
