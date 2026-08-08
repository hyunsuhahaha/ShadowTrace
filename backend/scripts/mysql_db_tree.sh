#!/usr/bin/env bash
# Lists every database and, per database, every table -- SHOW DATABASES
# doesn't show what's inside each one, and SHOW TABLES only covers one
# database at a time, so this chains them into the same D|/F| tree shape
# as the other tree commands.
set -uo pipefail

host="$1"
port="$2"
user="$3"
password="${4:-}"
timeout_seconds=15

mysql_args=(-h "$host" -P "$port" -u "$user" --skip-ssl --connect-timeout="$timeout_seconds" -N -B)
# MYSQL_PWD (not -p"$password") keeps the password out of argv/ps.
if [ -n "$password" ]; then
  export MYSQL_PWD="$password"
fi

databases=$(timeout "$timeout_seconds" mysql "${mysql_args[@]}" -e "SHOW DATABASES;" 2>&1)
if [ $? -ne 0 ]; then
  echo "[-] SHOW DATABASES 실패: $databases" >&2
  exit 1
fi

while IFS= read -r db; do
  [ -z "$db" ] && continue
  # These four never hold application data, just server metadata/views --
  # skipping them means real schemas surface immediately instead of
  # behind a wall of ~200 built-in introspection tables (verified count
  # live), and saves the extra round-trip per schema too.
  case "$db" in
    information_schema|performance_schema|mysql|sys) continue ;;
  esac
  echo "D|${db}"
  tables=$(timeout "$timeout_seconds" mysql "${mysql_args[@]}" -e "SHOW TABLES FROM \`${db}\`;" 2>/dev/null)
  while IFS= read -r table; do
    [ -z "$table" ] && continue
    echo "F|${db}/${table}"
  done <<< "$tables"
done <<< "$databases"
