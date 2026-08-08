"""Reconstructs a source tree from an exposed .svn working-copy directory
(the SVN equivalent of an exposed .git directory), tagged D|/F| like the
other tree commands.

Modern SVN (1.7+) working copies keep their metadata in a single SQLite
database (.svn/wc.db) rather than the old per-directory .svn/entries text
files, and store each file's actual content content-addressed under
.svn/pristine/<first two hex chars of its sha1>/<full sha1>.svn-base. So
unlike git-dumper (which has to replay a whole packed object history),
recovering the current working-copy snapshot here is: download wc.db,
query it locally for the file list, then fetch each pristine blob by hash.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


def _fetch(url: str, timeout: float) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconstruct a source tree from an exposed .svn directory.")
    parser.add_argument("--url", required=True,
                        help="Base URL of the exposed working copy, e.g. http://host/app/")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    base = args.url.rstrip("/")
    try:
        wc_db = _fetch(f"{base}/.svn/wc.db", args.timeout)
    except urllib.error.HTTPError as exc:
        print(f"[-] .svn/wc.db 다운로드 실패: HTTP {exc.code}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"[-] .svn/wc.db 다운로드 실패: {exc}", file=sys.stderr)
        return 1

    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        tmp.write(wc_db)
        tmp.flush()
        conn = sqlite3.connect(tmp.name)
        try:
            rows = conn.execute(
                "SELECT local_relpath, kind, checksum FROM NODES "
                "WHERE local_relpath != '' ORDER BY local_relpath"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            print(f"[-] wc.db를 읽을 수 없습니다: {exc}", file=sys.stderr)
            return 1
        finally:
            conn.close()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    fetched = 0
    for local_relpath, kind, checksum in rows:
        if kind == "dir":
            print(f"D|{local_relpath}")
            continue
        print(f"F|{local_relpath}")
        if not checksum or not checksum.startswith("$sha1$"):
            continue
        digest = checksum.removeprefix("$sha1$")
        pristine_url = f"{base}/.svn/pristine/{digest[:2]}/{digest}.svn-base"
        try:
            content = _fetch(pristine_url, args.timeout)
        except urllib.error.URLError:
            continue
        dest = output_dir / local_relpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        fetched += 1
    print(f"[+] {fetched}개 파일 복구 완료 -> {output_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
