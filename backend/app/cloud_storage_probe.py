"""Cloud object-storage fingerprinting via response header/body signatures.

AWS S3, Azure Blob Storage, Google Cloud Storage, and S3-compatible
software (MinIO etc.) all return an <Error><Code>...</Code></Error> body
for an unauthenticated/forbidden request, so the body shape alone is
ambiguous between them. Each backend's response carries a more distinct
signal instead: a Server header value and a family of provider-prefixed
headers (x-amz-*, x-ms-*, x-goog-*) that survive even when the XML body
itself looks identical across providers.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

_MAX_BODY = 65536
_ERROR_CODE = re.compile(r"<Code>([^<]+)</Code>", re.IGNORECASE)
_HAS_REQUEST_ID = re.compile(r"<RequestId>", re.IGNORECASE)
_HAS_HOST_ID = re.compile(r"<HostId>", re.IGNORECASE)


def _headers_with_prefix(headers: dict, prefix: str) -> list[str]:
    return sorted(key for key in headers if key.lower().startswith(prefix))


def classify_provider(headers: dict, body: str) -> dict:
    server = headers.get("Server", headers.get("server", ""))
    amz = _headers_with_prefix(headers, "x-amz-")
    ms = _headers_with_prefix(headers, "x-ms-")
    goog = _headers_with_prefix(headers, "x-goog-")
    match = _ERROR_CODE.search(body)
    error_code = match.group(1) if match else None

    if amz:
        if server.lower() == "amazons3":
            provider = "aws-s3"
        elif server.lower() == "minio":
            provider = "minio (s3-compatible)"
        else:
            provider = f"s3-compatible (Server: {server or 'unset'})"
    elif ms or "windows-azure-blob" in server.lower():
        provider = "azure-blob-storage"
    elif goog or server.lower() in ("uploadserver", "gse"):
        provider = "google-cloud-storage"
    elif error_code and _HAS_REQUEST_ID.search(body) and _HAS_HOST_ID.search(body):
        provider = "likely-s3-compatible (RequestId+HostId in body, no distinguishing headers)"
    else:
        provider = "unknown"

    return {
        "provider": provider, "server_header": server, "error_code": error_code,
        "amz_headers": amz, "ms_headers": ms, "goog_headers": goog,
    }


def fetch(url: str, timeout: float) -> tuple[int, dict, str]:
    scheme = url.split("://", 1)[0]
    context = ssl._create_unverified_context() if scheme == "https" else None
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        response = urllib.request.urlopen(request, timeout=timeout, context=context)
        status, headers, body = response.status, dict(response.headers), response.read(_MAX_BODY)
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers) if exc.headers else {}
        body = exc.read(_MAX_BODY) if exc.fp else b""
    return status, headers, body.decode("utf-8", "replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fingerprint an HTTP endpoint's cloud object-storage "
                    "backend from response headers/body.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--scheme", default="http", choices=("http", "https"))
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    url = f"{args.scheme}://{args.host}:{args.port}/"
    try:
        status, headers, body = fetch(url, args.timeout)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        result = {"url": url, "provider": "unknown", "reason": str(exc)}
    else:
        result = {"url": url, "status": status, **classify_provider(headers, body)}
    print(f"CLOUD_STORAGE_FINGERPRINT {json.dumps(result, ensure_ascii=False, sort_keys=True)}")
    return 0 if "status" in result else 1


if __name__ == "__main__":
    sys.exit(main())
