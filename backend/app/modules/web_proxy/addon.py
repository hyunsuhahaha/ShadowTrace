# mitmproxy addon: runs inside mitmdump's own process/interpreter, not the
# backend's. Keep this file stdlib + mitmproxy only (no backend imports, no
# extra pip deps) since it isn't installed into the backend's venv.
#
# Forwards every flow untouched (never flow.kill()) so the user's general
# browsing through the proxy keeps working; only flows bound for the scoped
# target IP get POSTed back to the backend for capture.
import base64
import json
import os
import urllib.error
import urllib.request

TARGET_IP = os.environ.get("OSCP_PROXY_TARGET_IP", "")
BACKEND_URL = os.environ.get("OSCP_BACKEND_URL", "http://127.0.0.1:8000")
PROJECT_ID = os.environ.get("OSCP_PROXY_PROJECT_ID", "")
TARGET_ID = os.environ.get("OSCP_PROXY_TARGET_ID", "")
CAPTURE_URL = BACKEND_URL.rstrip("/") + "/api/web/proxy/capture"


def response(flow):
    if not TARGET_IP or flow.request.host != TARGET_IP or not flow.response:
        return
    payload = {
        "project_id": int(PROJECT_ID),
        "target_id": int(TARGET_ID),
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "headers": dict(flow.request.headers.items()),
        "cookies": dict(flow.request.cookies.items()),
        "body": base64.b64encode(flow.request.content or b"").decode(),
        "status_code": flow.response.status_code,
        "response_headers": dict(flow.response.headers.items()),
        "response_cookies": {name: value[0]
                             for name, value in flow.response.cookies.items()},
        "response_body": base64.b64encode(flow.response.content or b"").decode(),
        "duration_ms": round((flow.response.timestamp_end -
                              flow.request.timestamp_start) * 1000),
    }
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        CAPTURE_URL, data=body, headers={"Content-Type": "application/json"},
        method="POST")
    try:
        urllib.request.urlopen(request, timeout=5).close()
    except urllib.error.URLError:
        pass  # backend unreachable; never break the user's own browsing
