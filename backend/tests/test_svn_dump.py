import hashlib
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from app.svn_dump import main


README_CONTENT = b"hello"
CONFIG_CONTENT = b"<?php $db='secret';"


def _make_wc_db(path: Path) -> None:
    """Builds a minimal wc.db with just the NODES columns svn_dump.py
    actually reads -- enough to exercise the real SQL query and file
    layout without needing a real svnadmin/svn checkout in the test."""
    readme_checksum = "$sha1$" + hashlib.sha1(README_CONTENT).hexdigest()
    config_checksum = "$sha1$" + hashlib.sha1(CONFIG_CONTENT).hexdigest()
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE NODES (local_relpath TEXT, kind TEXT, checksum TEXT)")
    conn.execute("INSERT INTO NODES VALUES ('', 'dir', NULL)")
    conn.execute("INSERT INTO NODES VALUES ('readme.txt', 'file', ?)", (readme_checksum,))
    conn.execute("INSERT INTO NODES VALUES ('src', 'dir', NULL)")
    conn.execute("INSERT INTO NODES VALUES ('src/config.php', 'file', ?)", (config_checksum,))
    conn.commit()
    conn.close()


def _make_site(tmp_path: Path) -> Path:
    site = tmp_path / "site"
    pristine = site / ".svn" / "pristine"
    for content in (README_CONTENT, CONFIG_CONTENT):
        digest = hashlib.sha1(content).hexdigest()
        folder = pristine / digest[:2]
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{digest}.svn-base").write_bytes(content)
    _make_wc_db(site / ".svn" / "wc.db")
    return site


def _serve(directory: Path) -> HTTPServer:
    handler = type("Handler", (BaseHTTPRequestHandler,), {})

    def do_GET(self):  # noqa: N802
        path = (directory / self.path.lstrip("/")).resolve()
        if directory.resolve() not in path.parents and path != directory.resolve():
            self.send_response(404); self.end_headers(); return
        if not path.is_file():
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(path.read_bytes())

    def log_message(self, *a):
        pass

    handler.do_GET = do_GET
    handler.log_message = log_message
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_svn_dump_recovers_the_exact_working_copy_from_an_exposed_svn_directory(tmp_path):
    site = _make_site(tmp_path)
    server = _serve(site)
    try:
        out_dir = tmp_path / "recovered"
        rc = main(["--url", f"http://127.0.0.1:{server.server_port}",
                   "--output-dir", str(out_dir)])
    finally:
        server.shutdown()

    assert rc == 0
    assert (out_dir / "readme.txt").read_bytes() == README_CONTENT
    assert (out_dir / "src" / "config.php").read_bytes() == CONFIG_CONTENT


def test_svn_dump_fails_cleanly_when_no_svn_directory_is_exposed(tmp_path):
    empty_site = tmp_path / "empty"
    empty_site.mkdir()
    server = _serve(empty_site)
    try:
        rc = main(["--url", f"http://127.0.0.1:{server.server_port}",
                   "--output-dir", str(tmp_path / "out")])
    finally:
        server.shutdown()
    assert rc == 1
