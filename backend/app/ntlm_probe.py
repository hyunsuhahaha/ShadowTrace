"""Unauthenticated NTLM target-info discovery.

Sends a static NTLM Type 1 (negotiate) token to common NTLM-auth HTTP(S)
endpoints (WinRM, IIS, etc.) and reads back the Type 2 challenge, which
Windows discloses without any credentials: NetBIOS/DNS domain and
computer name. This never attempts to authenticate -- it only completes
the first leg of a handshake the server offers unconditionally, the same
technique nmap's http-ntlm-info/rdp-ntlm-info scripts use.
"""
from __future__ import annotations

import argparse
import base64
import json
import ssl
import struct
import sys
import urllib.error
import urllib.request

DEFAULT_PORTS = [5985, 5986, 80, 443, 8080, 8443]
WINRM_PATHS = ["/wsman"]
HTTP_PATHS = ["/"]

_FLAGS = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000200  # unicode|oem|request_target|ntlm
_TYPE1 = base64.b64encode(
    b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", _FLAGS) + b"\x00" * 16
).decode()

_AV_NAMES = {
    1: "netbios_computer_name", 2: "netbios_domain_name",
    3: "dns_computer_name", 4: "dns_domain_name", 5: "dns_tree_name",
}


def _parse_type2(blob: bytes) -> dict:
    try:
        if blob[:8] != b"NTLMSSP\x00" or len(blob) < 20:
            return {}
        target_len, target_off = struct.unpack_from("<HxxI", blob, 12)
        result = {"target_name": blob[target_off:target_off + target_len]
                  .decode("utf-16le", "replace")}
        if len(blob) < 48:
            return result
        info_len, info_off = struct.unpack_from("<HxxI", blob, 40)
        info = blob[info_off:info_off + info_len]
        i = 0
        while i + 4 <= len(info):
            av_id, av_len = struct.unpack_from("<HH", info, i)
            i += 4
            if av_id == 0:
                break
            value = info[i:i + av_len]
            i += av_len
            name = _AV_NAMES.get(av_id)
            if name:
                result[name] = value.decode("utf-16le", "replace")
        return result
    except struct.error:
        return {}


def probe_endpoint(host: str, port: int, path: str, method: str, timeout: float) -> dict | None:
    scheme = "https" if port in (443, 5986, 8443) else "http"
    url = f"{scheme}://{host}:{port}{path}"
    body = b"probe" if method == "POST" else None
    request = urllib.request.Request(url, data=body, method=method, headers={
        "Authorization": f"Negotiate {_TYPE1}",
        "Content-Type": "application/soap+xml;charset=UTF-8",
    })
    context = ssl._create_unverified_context() if scheme == "https" else None
    try:
        urllib.request.urlopen(request, timeout=timeout, context=context)
        return None
    except urllib.error.HTTPError as exc:
        auth = exc.headers.get("WWW-Authenticate", "")
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    for scheme_name in ("Negotiate", "NTLM"):
        prefix = f"{scheme_name} "
        if auth.startswith(prefix) and len(auth) > len(prefix):
            try:
                blob = base64.b64decode(auth[len(prefix):])
            except ValueError:
                continue
            info = _parse_type2(blob)
            if info:
                return {"url": url, **info}
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Unauthenticated NTLM target-info discovery over common HTTP(S) NTLM endpoints.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS))
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args(argv)
    try:
        ports = [int(item) for item in args.ports.split(",") if item.strip()]
    except ValueError:
        parser.error("--ports must be a comma-separated list of integers")
    if not ports or not all(1 <= port <= 65535 for port in ports):
        parser.error("port is out of range")

    found = 0
    for port in ports:
        candidates = ([(path, "POST") for path in WINRM_PATHS]
                      + [(path, "GET") for path in HTTP_PATHS])
        for path, method in candidates:
            info = probe_endpoint(args.host, port, path, method, args.timeout)
            if info:
                found += 1
                print(f"NTLM_INFO {json.dumps({'port': port, **info}, ensure_ascii=False, sort_keys=True)}")
                break
    print(f"NTLM_INFO_SUMMARY ports_checked={len(ports)} found={found}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
