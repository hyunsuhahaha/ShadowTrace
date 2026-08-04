#!/usr/bin/env bash
# Runs nmap's mysql-brute.nse against a user-supplied candidate list via
# unpwdb's userdb/passdb script-args, instead of nmap's own generic top-N
# cut of its bundled wordlists (unpwdb.userlimit/passlimit). Same candidate
# source as mysql_credential_probe.sh, so both checks track what's typed
# into the UI rather than a number someone picked once and hardcoded.
set -uo pipefail

host="$1"
port="$2"
user_list="${3:-root,mysql,admin}"
password_list="${4:-,root,mysql,password}"

userdb=$(mktemp)
passdb=$(mktemp)
trap 'rm -f "$userdb" "$passdb"' EXIT

IFS=',' read -ra users <<< "$user_list"
IFS=',' read -ra passwords <<< "$password_list"
printf '%s\n' "${users[@]}" > "$userdb"
printf '%s\n' "${passwords[@]}" > "$passdb"

# Not `exec`: that would replace this process with nmap's, which skips the
# EXIT trap above and leaks the temp wordlist files.
nmap -Pn -p"$port" --script mysql-brute --script-args \
  "userdb=$userdb,passdb=$passdb,brute.start=2,brute.threads=2,brute.delay=2,brute.guesses=3,brute.firstonly=true,brute.retries=0,unpwdb.timelimit=2m,mysql-brute.timeout=30" \
  "$host"
