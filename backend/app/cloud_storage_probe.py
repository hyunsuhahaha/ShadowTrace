"""Cloud object-storage fingerprinting via response header/body signatures.

AWS S3, Azure Blob Storage, Google Cloud Storage, and S3-compatible
software (MinIO etc.) all return an <Error><Code>...</Code></Error> body
for an unauthenticated/forbidden request, so the body shape alone is
ambiguous between them. Each backend's response carries a more distinct
signal instead: a Server header value and a family of provider-prefixed
headers (x-amz-*, x-ms-*, x-goog-*) that survive even when the XML body
itself looks identical across providers.

The error code inside that same body carries a second, independent
signal: not which provider this is, but what the failure actually means
(a private-but-real bucket vs. a nonexistent one vs. an endpoint that
demands real credentials) — interpret_error_code() maps the common
codes to that meaning and a suggested next step.
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

# What the error code itself implies about the resource, independent of
# which provider returned it — an unauthenticated GET can fail for very
# different reasons (private-but-real vs. simply-doesn't-exist vs.
# "this isn't even an anonymous-access surface"), and that distinction
# decides the next enumeration step more than the provider name does.
_ERROR_MEANINGS = {
    "accessdenied": (
        "리소스(버킷/컨테이너)는 존재하지만 익명 접근 권한이 없습니다 (ACL·정책이 비공개).",
        "알고 있는 파일 경로로 직접 접근을 시도하거나, 다른 경로로 자격증명을 확보한 뒤 재시도하세요.",
    ),
    "nosuchbucket": (
        "요청한 버킷 이름 자체가 존재하지 않습니다.",
        "버킷 이름 철자·조합을 다시 확인하세요 (cloud_enum으로 후보를 넓혀볼 수 있습니다).",
    ),
    "nosuchkey": (
        "버킷은 존재하지만 요청한 파일(키)이 없습니다.",
        "파일 경로·이름을 다시 확인하거나 버킷 파일 목록 조회로 실제 파일명을 확인하세요.",
    ),
    "invalidaccesskeyid": (
        "익명 접근이 아니라 실제 인증(Access Key)이 필요한 API 엔드포인트입니다.",
        "유효한 자격증명 없이는 더 진행할 수 없습니다 — 다른 경로에서 자격증명을 찾아보세요.",
    ),
    "signaturedoesnotmatch": (
        "자격증명은 전달됐지만 서명 검증에 실패했습니다 (잘못된 시크릿·시간 오차 등).",
        "사용 중인 자격증명(Access Key/Secret)이 올바른지, 시스템 시간이 맞는지 확인하세요.",
    ),
    "allaccessdisabled": (
        "버킷은 존재하지만 소유자가 모든 접근(소유자 포함)을 차단했습니다.",
        "이 경로로는 더 진행할 수 없습니다 — 다른 버킷·경로를 확인하세요.",
    ),
    "resourcenotfound": (
        "Azure 컨테이너 또는 블롭이 존재하지 않습니다.",
        "컨테이너·블롭 이름을 다시 확인하세요.",
    ),
    "containernotfound": (
        "Azure 컨테이너가 존재하지 않습니다.",
        "컨테이너 이름을 다시 확인하세요.",
    ),
    "blobnotfound": (
        "Azure 블롭(파일)이 존재하지 않습니다.",
        "블롭 이름을 다시 확인하거나 컨테이너 목록을 먼저 확인하세요.",
    ),
    "publicaccessnotpermitted": (
        "Azure 컨테이너가 비공개로 설정되어 있습니다 (컨테이너는 존재).",
        "익명 접근이 막혀 있습니다 — SAS 토큰이나 스토리지 계정 키가 필요합니다.",
    ),
    "authenticationfailed": (
        "Azure 인증에 실패했습니다 — 이 엔드포인트는 유효한 자격증명을 요구합니다.",
        "SAS 토큰이나 스토리지 계정 키를 확보해야 진행할 수 있습니다.",
    ),
}


def interpret_error_code(error_code: str | None) -> dict | None:
    if not error_code:
        return None
    entry = _ERROR_MEANINGS.get(error_code.lower())
    if not entry:
        return None
    meaning, next_step = entry
    return {"meaning": meaning, "next_step": next_step}


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

    interpretation = interpret_error_code(error_code) or {"meaning": None, "next_step": None}
    return {
        "provider": provider, "server_header": server, "error_code": error_code,
        "amz_headers": amz, "ms_headers": ms, "goog_headers": goog,
        **interpretation,
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
