"""Lists every IMAP mailbox (folder) via LIST "" "*", tagged like the other
tree commands.

Unlike a filesystem, every listed mailbox is itself directly selectable
(readable) even if it also has children, so there's no real dir-vs-file
distinction here -- every mailbox is tagged F|, and the shared frontend
tree builder already turns intermediate path segments (INBOX in
INBOX/Sent/2024) into expandable branches on its own from the full path,
the same way it does for the other tree commands.
"""
from __future__ import annotations

import argparse
import imaplib
import re
import sys

LIST_RE = re.compile(r'^\((?P<flags>[^)]*)\)\s+"(?P<delim>[^"]*)"\s+(?P<name>.+)$')


def parse_list_line(line: bytes) -> tuple[str, str] | None:
    """Returns (delimiter, mailbox_name) or None if the line doesn't match
    the RFC 3501 LIST response shape."""
    match = LIST_RE.match(line.decode(errors="replace"))
    if not match:
        return None
    delim = match.group("delim")
    name = match.group("name").strip()
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1]
    return delim, name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List every IMAP mailbox as a tree.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    try:
        client = (imaplib.IMAP4_SSL(args.host, args.port, timeout=args.timeout)
                  if args.port == 993
                  else imaplib.IMAP4(args.host, args.port, timeout=args.timeout))
    except OSError as exc:
        print(f"[-] {args.host}:{args.port} 연결 실패: {exc}", file=sys.stderr)
        return 1
    try:
        client.login(args.username, args.password)
    except imaplib.IMAP4.error as exc:
        print(f"[-] 로그인 실패: {exc}", file=sys.stderr)
        return 1
    try:
        typ, data = client.list()
        if typ != "OK":
            print("[-] LIST 실패", file=sys.stderr)
            return 1
        for raw_line in data:
            parsed = parse_list_line(raw_line)
            if not parsed:
                continue
            delim, name = parsed
            path = name.replace(delim, "/") if delim else name
            print(f"F|{path}")
    finally:
        client.logout()
    return 0


if __name__ == "__main__":
    sys.exit(main())
