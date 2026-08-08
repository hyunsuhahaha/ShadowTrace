#!/usr/bin/env bash
# Unlike MySQL, a single PostgreSQL connection is scoped to one database --
# pg_database lists every database, but listing what's inside each one
# needs a separate connection per database (same shape as MySQL's tree
# script, just one extra round-trip per database instead of a single
# connection reused for SHOW TABLES FROM).
set -uo pipefail

host="$1"
port="$2"
user="$3"
password="${4:-}"
timeout_seconds=15

# PGPASSWORD (not a CLI flag) keeps the password out of argv/ps.
if [ -n "$password" ]; then
  export PGPASSWORD="$password"
fi

psql_args=(-h "$host" -p "$port" -U "$user" -X -q -t -A)

databases=$(timeout "$timeout_seconds" psql "${psql_args[@]}" -d postgres \
  -c "SELECT datname FROM pg_database WHERE datistemplate = false;" 2>&1)
if [ $? -ne 0 ]; then
  echo "[-] 데이터베이스 목록 조회 실패: $databases" >&2
  exit 1
fi

while IFS= read -r db; do
  [ -z "$db" ] && continue
  echo "D|${db}"
  tables=$(timeout "$timeout_seconds" psql "${psql_args[@]}" -d "$db" -c \
    "SELECT table_schema || '.' || table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema');" 2>/dev/null)
  while IFS= read -r table; do
    [ -z "$table" ] && continue
    echo "F|${db}/${table}"
  done <<< "$tables"
done <<< "$databases"
