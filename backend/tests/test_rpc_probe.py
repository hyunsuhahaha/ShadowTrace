from app.rpc_probe import Endpoint, classify_error, tcp_binding
from app.templates import catalog as command_catalog


def test_tcp_binding_replaces_advertised_host_but_keeps_dynamic_port():
    assert tcp_binding("ncacn_ip_tcp:SERVER01[49664]", "10.10.10.10") == (
        "ncacn_ip_tcp:10.10.10.10[49664]")
    assert tcp_binding("ncacn_np:SERVER01[\\pipe\\samr]", "10.10.10.10") is None


def test_bind_errors_are_structured_for_branching():
    assert classify_error(Exception("rpc_s_access_denied")) == "access_denied"
    assert classify_error(Exception("authentication required")) == "authentication_required"
    assert classify_error(Exception("connection timed out")) == "unreachable"
    assert classify_error(Exception("abstract_syntax_not_supported")) == "not_supported"


def test_endpoint_is_an_immutable_record():
    row = Endpoint("uuid v1.0", "Service", "ncacn_ip_tcp:host[50000]")
    assert row.binding.endswith("[50000]")


def test_rpc_command_uses_server_controlled_repository_path():
    _, command, argv = command_catalog.render("msrpc-enum", {
        "host": "10.10.10.10", "port": "135", "repo_dir": "/opt/oscp workspace",
    })
    assert argv[:4] == ["/opt/oscp workspace/.venv/bin/python", "-m", "app.rpc_probe", "endpoints"]
    assert "--host 10.10.10.10" in command
