"""Recursive FTP directory/file listing, tagged D|/F| like the WinRM/SSH
file-tree commands so the frontend can render all three with the same
tree widget.

FTP has no built-in recursive listing (unlike SMB's `recurse ON;ls`), so
this walks directories one at a time. MLSD (RFC 3659, machine-readable)
is tried first since it unambiguously reports type=dir/file; servers old
enough not to support it (still common on HTB/OSCP boxes -- older IIS FTP
in particular) fall back to parsing a Unix-style LIST response.

This also doubles as the login check for both anonymous and credentialed
FTP: a wrong password fails at login() before any listing is attempted,
so a non-zero exit here is a clean "login failed" signal on its own.
"""
from __future__ import annotations

import argparse
import ftplib
import re
import sys

MAX_ENTRIES = 2000
MAX_DEPTH = 12
_LIST_RE = re.compile(r"^([-dl])\S{9}\s+.*?\s(\S+)$")


def _mlsd_entries(ftp: ftplib.FTP, path: str) -> list[tuple[str, bool]] | None:
    try:
        return [(name, facts.get("type") == "dir")
                for name, facts in ftp.mlsd(path) if name not in (".", "..")]
    except (ftplib.error_perm, ftplib.error_proto):
        return None


def _list_entries(ftp: ftplib.FTP, path: str) -> list[tuple[str, bool]]:
    lines: list[str] = []
    ftp.retrlines(f"LIST {path}", lines.append)
    entries = []
    for line in lines:
        m = _LIST_RE.match(line.strip())
        if m and m.group(2) not in (".", ".."):
            entries.append((m.group(2), m.group(1) == "d"))
    return entries


def walk(ftp: ftplib.FTP, path: str, depth: int, budget: list[int]) -> list[str]:
    if depth > MAX_DEPTH or budget[0] <= 0:
        return []
    entries = _mlsd_entries(ftp, path)
    if entries is None:
        entries = _list_entries(ftp, path)
    lines = []
    for name, is_dir in sorted(entries):
        if budget[0] <= 0:
            break
        child = f"{path}/{name}" if path else name
        lines.append(f"{'D' if is_dir else 'F'}|{child}")
        budget[0] -= 1
        if is_dir:
            lines.extend(walk(ftp, child, depth + 1, budget))
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recursive FTP directory/file tree.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=21)
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    ftp = ftplib.FTP()
    try:
        ftp.connect(args.host, args.port, timeout=args.timeout)
    except OSError as exc:
        print(f"[-] {args.host}:{args.port} 연결 실패: {exc}", file=sys.stderr)
        return 1
    try:
        ftp.login(args.username or "anonymous", args.password or "anonymous@")
    except ftplib.error_perm as exc:
        print(f"[-] 로그인 실패: {exc}", file=sys.stderr)
        ftp.close()
        return 1
    try:
        for line in walk(ftp, "", 0, [MAX_ENTRIES]):
            print(line)
    finally:
        ftp.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
