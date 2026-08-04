"""Canonical-hostname discovery via HTTP redirect disclosure.

Some sites bind a DNS-style vhost (e.g. an Apache ServerName) and, when
reached by bare IP, immediately disclose that name via a 3xx Location
header or an HTML <meta http-equiv="refresh"> tag -- the site telling a
client its own canonical hostname, unprompted and without
authentication. This is a stronger signal than reverse-DNS (works even
with no PTR record) and, unlike an NTLM info leak, names the actual
site hostname rather than the underlying machine's identity.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_PORTS = [80, 443, 8080, 8443]
_META_REFRESH = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>]+)',
    re.IGNORECASE)
_MAX_BODY = 65536


def _is_own_host(hostname: str, host: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return hostname.strip("[]").lower() == host.lower()


def probe_port(host: str, port: int, timeout: float) -> dict | None:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    context = ssl._create_unverified_context() if scheme == "https" else None
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        response = urllib.request.urlopen(request, timeout=timeout, context=context)
        final_url, body = response.geturl(), response.read(_MAX_BODY)
    except urllib.error.HTTPError as exc:
        final_url = exc.geturl()
        body = exc.read(_MAX_BODY) if exc.fp else b""
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    body = body.decode("utf-8", "replace")

    final_host = urlparse(final_url).hostname or ""
    if final_host and not _is_own_host(final_host, host):
        return {"url": url, "hostname": final_host, "via": "redirect"}

    match = _META_REFRESH.search(body)
    if match:
        target_host = urlparse(match.group(1).strip()).hostname or ""
        if target_host and not _is_own_host(target_host, host):
            return {"url": url, "hostname": target_host, "via": "meta-refresh"}
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover a site's canonical hostname via HTTP redirect/meta-refresh disclosure.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS))
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        ports = [int(item) for item in args.ports.split(",") if item.strip()]
    except ValueError:
        parser.error("--ports must be a comma-separated list of integers")
    if not ports or not all(1 <= port <= 65535 for port in ports):
        parser.error("port is out of range")

    found = 0
    for port in ports:
        info = probe_port(args.host, port, args.timeout)
        if info:
            found += 1
            print(f"REDIRECT_HOSTNAME {json.dumps({'port': port, **info}, ensure_ascii=False, sort_keys=True)}")
    print(f"REDIRECT_HOSTNAME_SUMMARY ports_checked={len(ports)} found={found}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
