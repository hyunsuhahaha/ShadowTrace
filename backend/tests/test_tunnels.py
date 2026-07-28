from app.modules.tunnels.router import render
from app.schemas import TunnelIn


def test_user_confirmed_local_tunnel_renders_argv_without_shell():
    body = TunnelIn(
        project_id=1, target_id=2, name="manual pivot", kind="local",
        ssh_host="10.10.10.10", username="student", bind_host="127.0.0.1",
        local_port=8080, remote_host="10.10.20.5", remote_port=80,
        confirmed=True)
    argv = render(body)
    assert argv[0] == "ssh"
    assert argv[-1] == "student@10.10.10.10"
    assert "127.0.0.1:8080:10.10.20.5:80" in argv


def test_tunnel_requires_explicit_scope_confirmation():
    body = TunnelIn(
        project_id=1, target_id=2, name="manual pivot", kind="dynamic",
        ssh_host="10.10.10.10", username="student", local_port=1080,
        confirmed=False)
    try:
        render(body)
    except ValueError:
        return
    raise AssertionError("unconfirmed tunnel was accepted")
