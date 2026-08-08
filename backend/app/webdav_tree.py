"""Recursive WebDAV directory/file listing via PROPFIND, tagged D|/F| like
the other file-tree commands.

Depth: infinity is not honored consistently across servers (some outright
reject it), so this walks one directory at a time with Depth: 1 instead --
the same per-directory-recursion shape as the FTP tree walker, just over
HTTP.
"""
from __future__ import annotations

import argparse
import base64
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NS = "DAV:"
MAX_ENTRIES = 2000
MAX_DEPTH = 12


def _list_dir(base_url: str, request_path: str, auth_header: str | None,
              timeout: float) -> list[tuple[str, bool]]:
    """PROPFIND on request_path (an absolute path on base_url's server) at
    Depth: 1, returning that directory's immediate children."""
    url = base_url.rstrip("/") + request_path
    headers = {"Depth": "1", "Content-Type": "application/xml"}
    if auth_header:
        headers["Authorization"] = auth_header
    request = urllib.request.Request(url, method="PROPFIND", headers=headers)
    context = ssl._create_unverified_context() if url.startswith("https") else None
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        root = ET.fromstring(response.read())

    normalized_request_path = request_path.rstrip("/") or "/"
    entries = []
    for item in root.findall(f"{{{NS}}}response"):
        href = item.findtext(f"{{{NS}}}href") or ""
        href_path = urllib.parse.unquote(urllib.parse.urlsplit(href).path)
        href_path = href_path.rstrip("/") or "/"
        if href_path == normalized_request_path:
            continue  # PROPFIND always echoes the requested collection itself first
        name = href_path.rsplit("/", 1)[-1]
        is_dir = item.find(f".//{{{NS}}}resourcetype/{{{NS}}}collection") is not None
        entries.append((name, is_dir))
    return entries


def walk(base_url: str, start_path: str, rel_path: str, auth_header: str | None,
          timeout: float, depth: int, budget: list[int]) -> list[str]:
    if depth > MAX_DEPTH or budget[0] <= 0:
        return []
    request_path = start_path.rstrip("/") + (f"/{rel_path}" if rel_path else "")
    try:
        entries = _list_dir(base_url, request_path, auth_header, timeout)
    except (urllib.error.URLError, ET.ParseError):
        return []
    lines = []
    for name, is_dir in sorted(entries):
        if budget[0] <= 0:
            break
        child = f"{rel_path}/{name}" if rel_path else name
        lines.append(f"{'D' if is_dir else 'F'}|{child}")
        budget[0] -= 1
        if is_dir:
            lines.extend(walk(base_url, start_path, child, auth_header, timeout,
                              depth + 1, budget))
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recursive WebDAV directory/file tree.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--scheme", default="http", choices=["http", "https"])
    parser.add_argument("--path", default="/")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    base_url = f"{args.scheme}://{args.host}:{args.port}"
    auth_header = None
    if args.username:
        token = base64.b64encode(f"{args.username}:{args.password}".encode()).decode()
        auth_header = f"Basic {token}"

    try:
        _list_dir(base_url, args.path, auth_header, args.timeout)
    except urllib.error.HTTPError as exc:
        print(f"[-] PROPFIND 실패: HTTP {exc.code}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, ET.ParseError) as exc:
        print(f"[-] PROPFIND 실패: {exc}", file=sys.stderr)
        return 1

    for line in walk(base_url, args.path, "", auth_header, args.timeout, 0, [MAX_ENTRIES]):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
