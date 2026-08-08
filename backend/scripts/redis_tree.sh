#!/usr/bin/env bash
# KEYS * returns every key in one request (no recursion needed). Redis has
# no real directory structure, but apps commonly namespace keys with ":"
# (user:1:profile, session:abc) -- splitting on that gives the same
# expandable-tree experience as the other tree commands, and a deployment
# that doesn't use the convention just falls back to a flat list, same as
# any other flat store would.
set -uo pipefail

host="$1"
port="$2"
password="${3:-}"

# REDISCLI_AUTH (env var, not -a) keeps the password out of argv/ps.
if [ -n "$password" ]; then
  export REDISCLI_AUTH="$password"
fi

# redis-cli always exits 0 here regardless of auth outcome -- a wrong
# password still prints "AUTH failed: ..." and then tries (and fails) the
# real command, both to stdout, so those lines have to be caught by content
# rather than by exit code (verified live against a real password-
# protected server: exit code stayed 0 in every case tried).
output=$(redis-cli -h "$host" -p "$port" --no-auth-warning KEYS '*')
if grep -qE "AUTH failed|NOAUTH" <<< "$output"; then
  echo "[-] 인증 실패" >&2
  exit 1
fi

grep -v '^$' <<< "$output" | sed 's/:/\//g; s/^/F|/'
exit 0  # an empty result (0 keys) is a real, non-error outcome, not a
        # failure -- grep above exits 1 when it filters everything out
