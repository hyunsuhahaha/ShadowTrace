#!/usr/bin/env bash
# rsync --list-only -r already recurses the whole module in one request (no
# per-directory walking needed, unlike FTP/NFS/WebDAV) -- this just tags
# each line D|/F| like the other tree commands and drops the "." entry
# rsync always lists first, which is the module root itself.
set -uo pipefail

host="$1"
port="$2"
module="$3"

rsync -r --list-only "rsync://${host}:${port}/${module}/" | awk '
  $NF != "." {
    tag = (substr($1, 1, 1) == "d") ? "D" : "F"
    $1 = $2 = $3 = $4 = ""
    sub(/^ +/, "")
    print tag "|" $0
  }
'
