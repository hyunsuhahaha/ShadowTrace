import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.webdav_tree import walk

# A minimal fake WebDAV server (stdlib http.server, no real DAV logic) that
# answers PROPFIND Depth:1 with canned multistatus XML for a small fixed
# tree, keyed by request path -- enough to exercise the real recursion and
# XML-parsing code against real HTTP requests instead of a mocked client.
TREE = {
    "/": [("pub", True), ("readme.txt", False)],
    "/pub": [("notes.txt", False), ("backups", True)],
    "/pub/backups": [("site.zip", False)],
}


def _multistatus(request_path: str, entries: list[tuple[str, bool]]) -> bytes:
    base = request_path.rstrip("/")
    responses = [f"<D:response><D:href>{base}/</D:href></D:response>"]
    for name, is_dir in entries:
        collection = "<D:collection/>" if is_dir else ""
        responses.append(
            f"<D:response><D:href>{base}/{name}</D:href>"
            f"<D:propstat><D:prop><D:resourcetype>{collection}"
            "</D:resourcetype></D:prop></D:propstat></D:response>"
        )
    body = "<D:multistatus xmlns:D=\"DAV:\">" + "".join(responses) + "</D:multistatus>"
    return body.encode()


class FakeWebDavHandler(BaseHTTPRequestHandler):
    def do_PROPFIND(self):  # noqa: N802 - matches http.server's do_<METHOD> convention
        path = self.path.rstrip("/") or "/"
        if path not in TREE:
            self.send_response(404)
            self.end_headers()
            return
        body = _multistatus(path, TREE[path])
        self.send_response(207)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # silence per-request logging
        pass


def _start_server() -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), FakeWebDavHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_walk_recursively_tags_directories_and_files_over_real_http():
    server = _start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        lines = walk(base_url, "/", "", None, 5.0, 0, [2000])
    finally:
        server.shutdown()
    assert lines == [
        "D|pub", "D|pub/backups", "F|pub/backups/site.zip", "F|pub/notes.txt",
        "F|readme.txt",
    ]


def test_walk_stops_at_the_entry_budget():
    server = _start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        lines = walk(base_url, "/", "", None, 5.0, 0, [2])
    finally:
        server.shutdown()
    assert lines == ["D|pub", "D|pub/backups"]


def test_walk_skips_a_directory_it_cannot_propfind_instead_of_crashing():
    server = _start_server()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        lines = walk(base_url, "/does-not-exist", "", None, 5.0, 0, [2000])
    finally:
        server.shutdown()
    assert lines == []
