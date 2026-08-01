"""Safe MSRPC endpoint discovery and interface bind checks.

This module never calls an interface operation.  It queries the endpoint
mapper and, in bind mode, performs only the DCE/RPC bind handshake advertised
by each TCP endpoint.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass

from impacket import uuid
from impacket.dcerpc.v5 import epm, transport


@dataclass(frozen=True)
class Endpoint:
    interface: str
    annotation: str
    binding: str


def _transport(binding: str, timeout: float):
    rpc_transport = transport.DCERPCTransportFactory(binding)
    rpc_transport.set_connect_timeout(timeout)
    return rpc_transport


def discover(host: str, port: int, timeout: float = 4.0) -> list[Endpoint]:
    binding = f"ncacn_ip_tcp:{host}[{port}]"
    rpc_transport = _transport(binding, timeout)
    dce = rpc_transport.get_dce_rpc()
    try:
        dce.connect()
        entries = epm.hept_lookup(None, dce=dce)
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass
    result: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        interface = str(entry["tower"]["Floors"][0])
        advertised = epm.PrintStringBinding(entry["tower"]["Floors"])
        annotation = entry.get("annotation", b"")
        if isinstance(annotation, bytes):
            annotation = annotation.rstrip(b"\x00").decode("utf-8", "replace")
        key = (interface, advertised)
        if key in seen:
            continue
        seen.add(key)
        result.append(Endpoint(interface, str(annotation), advertised))
    return result


def tcp_binding(binding: str, host: str) -> str | None:
    match = re.fullmatch(r"ncacn_ip_tcp:[^\[]+\[(\d+)\]", binding)
    return f"ncacn_ip_tcp:{host}[{match.group(1)}]" if match else None


def classify_error(reason: Exception) -> str:
    text = str(reason).lower()
    if any(token in text for token in (
        "access_denied", "access denied", "rpc_s_access_denied",
        "nca_s_fault_access_denied",
    )):
        return "access_denied"
    if any(token in text for token in (
        "logon", "credential", "authentication", "sec_pkg", "ntlm",
    )):
        return "authentication_required"
    if any(token in text for token in (
        "timed out", "timeout", "connection refused", "no route",
        "unreachable",
    )):
        return "unreachable"
    if "abstract_syntax_not_supported" in text:
        return "not_supported"
    return "error"


def check_bind(endpoint: Endpoint, host: str, timeout: float = 4.0) -> dict:
    binding = tcp_binding(endpoint.binding, host)
    if not binding:
        return {**asdict(endpoint), "outcome": "not_tcp", "detail": ""}
    dce = _transport(binding, timeout).get_dce_rpc()
    try:
        dce.connect()
        syntax = uuid.uuidtup_to_bin(uuid.string_to_uuidtup(endpoint.interface))
        dce.bind(syntax)
        outcome, detail = "bind_ok", ""
    except Exception as exc:
        outcome, detail = classify_error(exc), str(exc)[:500]
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass
    return {**asdict(endpoint), "binding": binding,
            "outcome": outcome, "detail": detail}


def emit(kind: str, row: dict) -> None:
    print(f"{kind} {json.dumps(row, ensure_ascii=False, sort_keys=True)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Query MSRPC endpoints and optionally test DCE/RPC binds without method calls.")
    parser.add_argument("mode", choices=("endpoints", "bind"))
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=135)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--max-bindings", type=int, default=64)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or not 1 <= args.max_bindings <= 256:
        parser.error("port or max-bindings is out of range")
    try:
        endpoints = discover(args.host, args.port, args.timeout)
    except Exception as exc:
        emit("RPC_PROBE_ERROR", {"phase": "endpoint_mapper",
                                  "outcome": classify_error(exc),
                                  "detail": str(exc)[:500]})
        return 2
    for endpoint in endpoints:
        emit("RPC_ENDPOINT", asdict(endpoint))
    if args.mode == "endpoints":
        print(f"RPC_ENDPOINT_SUMMARY count={len(endpoints)}")
        return 0
    checked = 0
    for endpoint in endpoints:
        if tcp_binding(endpoint.binding, args.host) and checked < args.max_bindings:
            emit("RPC_BIND_RESULT", check_bind(endpoint, args.host, args.timeout))
            checked += 1
    print(f"RPC_BIND_SUMMARY endpoints={len(endpoints)} checked={checked}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
