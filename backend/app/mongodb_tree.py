"""Lists every database and collection a MongoDB connection can see,
tagged like the other tree commands.

mongodb-info already confirms unauthenticated access works before this
ever runs, so this doesn't attempt any auth itself -- just an
unauthenticated connection, same as that check.
"""
from __future__ import annotations

import argparse
import sys

import pymongo
import pymongo.errors

# Never hold application data, just server-internal bookkeeping -- same
# reasoning as skipping MySQL's information_schema/performance_schema/
# mysql/sys in mysql_db_tree.sh.
SYSTEM_DATABASES = {"admin", "local", "config"}


def build_tree_lines(client) -> list[str]:
    lines = []
    for db_name in sorted(client.list_database_names()):
        if db_name in SYSTEM_DATABASES:
            continue
        lines.append(f"D|{db_name}")
        for collection in sorted(client[db_name].list_collection_names()):
            lines.append(f"F|{db_name}/{collection}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List every MongoDB database/collection as a tree.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    client = pymongo.MongoClient(
        args.host, args.port,
        serverSelectionTimeoutMS=int(args.timeout * 1000),
        connectTimeoutMS=int(args.timeout * 1000),
    )
    try:
        for line in build_tree_lines(client):
            print(line)
    except pymongo.errors.PyMongoError as exc:
        print(f"[-] 연결 실패: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
