#!/usr/bin/env bash
# Runs one command over WinRM via NetExec and strips nxc's own
# "PROTOCOL  IP  PORT  HOSTNAME  " prefix from every output line, so the
# captured stdout is just the command's own output like every other
# tree/probe script in this app (verified live: nxc prefixes every single
# line of command output with those four columns, not just its own status
# lines).
set -uo pipefail

host="$1"
username="$2"
secret_kind="$3"  # "password" or "hash"
secret_path="$4"  # file containing just the secret -- both -p and -H
                   # accept a file path directly (verified live), so the
                   # secret itself never appears in this argv or nxc's own
domain="${5:-}"
command="$6"

args=(winrm "$host" -u "$username")
if [ "$secret_kind" = "hash" ]; then
  args+=(-H "$secret_path")
else
  args+=(-p "$secret_path")
fi
[ -n "$domain" ] && args+=(-d "$domain")
args+=(-x "$command")

# nxc's own visible output finishes in ~8s (verified live, repeatedly), but
# when this whole script runs under the app's asyncio subprocess capture
# (PIPE-based stdout, unlike a normal terminal) the parent bash process
# doesn't get reaped until close to this catalog command's full 120s
# timeout even though the command's real work is long done -- reproduced
# live, not yet root-caused (didn't reproduce standalone outside the app
# no matter how closely the invocation was mirrored: piped through sed,
# stdin from /dev/null, etc). `timeout` bounds the wait to a fraction of
# that instead of trusting nxc's own exit timing.
timeout --kill-after=5 30 nxc "${args[@]}" \
  | sed -E 's/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+//'
