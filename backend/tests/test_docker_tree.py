import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.docker_tree import build_tree_lines, main

CONTAINERS = [
    {"Id": "abc123", "Names": ["/web"], "Image": "nginx:latest", "State": "running"},
    {"Id": "def456", "Names": ["/db"], "Image": "postgres:15", "State": "exited"},
]
IMAGES = [
    {"Id": "sha256:aaa", "RepoTags": ["nginx:latest"]},
    {"Id": "sha256:bbb", "RepoTags": ["postgres:15", "postgres:latest"]},
    {"Id": "sha256:ccc", "RepoTags": None},
]


def test_build_tree_lines_tags_containers_and_images():
    assert build_tree_lines(CONTAINERS, IMAGES) == [
        "D|containers",
        "F|containers/web",
        "F|containers/db",
        "D|images",
        "F|images/nginx:latest",
        "F|images/postgres:15",
        "F|images/postgres:latest",
        "F|images/sha256:ccc",
    ]


def test_build_tree_lines_handles_no_containers_or_images():
    assert build_tree_lines([], []) == ["D|containers", "D|images"]


class FakeDockerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/containers/json?all=true":
            body = json.dumps(CONTAINERS).encode()
        elif self.path == "/images/json":
            body = json.dumps(IMAGES).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def test_main_fetches_and_prints_the_tree_over_real_http():
    server = HTTPServer(("127.0.0.1", 0), FakeDockerHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        rc = main(["--host", "127.0.0.1", "--port", str(server.server_port)])
    finally:
        server.shutdown()
    assert rc == 0


def test_main_fails_cleanly_against_an_unreachable_port():
    rc = main(["--host", "127.0.0.1", "--port", "1", "--timeout", "1"])
    assert rc == 1
