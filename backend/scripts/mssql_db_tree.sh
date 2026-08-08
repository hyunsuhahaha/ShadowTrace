#!/usr/bin/env bash
# sp_MSforeachdb (undocumented but present on every mainstream SQL Server
# edition) loops the given command once per database, substituting ? for
# the database name each time -- one round trip lists every database AND
# every table in it, unlike MySQL/PostgreSQL which each need a query per
# database. The query itself emits already-tagged "D|db" / "F|db/table"
# result rows so there's nothing to parse out of impacket-mssqlclient's
# own column-formatted output beyond matching lines starting with D|/F|
# (verified against impacket's tds.py printRows: values are padded with
# trailing spaces to the column width, which .trim() on the frontend
# already strips -- this specific query was not verified against a real
# SQL Server, since none was available to test against locally).
set -uo pipefail

host="$1"
port="$2"
user="$3"
password="${4:-}"
domain="${5:-}"

target="${user}"
[ -n "$domain" ] && target="${domain}/${target}"
[ -n "$password" ] && target="${target}:${password}"
target="${target}@${host}"

query="EXEC sp_MSforeachdb 'SELECT ''D|?''; SELECT ''F|?/'' + TABLE_NAME FROM [?].INFORMATION_SCHEMA.TABLES'"

impacket-mssqlclient "$target" -port "$port" -command "$query"
