#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "The backend launcher must run through sudo." >&2
  exit 1
fi
: "${OSCP_WORKSPACE_OWNER_GID:?missing owner gid}"
: "${OSCP_WORKSPACE_CONFIG:?missing config path}"
: "${OSCP_WORKSPACE_DATA:?missing data path}"
: "${OSCP_WORKSPACE_STATE:?missing state path}"
: "${OSCP_WORKSPACE_ROOT:?missing workspace path}"
cd "$(dirname "$0")/.."
umask 0002
export OSCP_ALLOW_ROOT=1 OSCP_BACKEND_BIND=127.0.0.1 PYTHONDONTWRITEBYTECODE=1
child=""
pid_file="$OSCP_WORKSPACE_STATE/root-backend.pid"
cleanup() {
  trap - EXIT HUP INT TERM
  if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
    kill -TERM -- "-$child" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$child" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL -- "-$child" 2>/dev/null || true
  fi
  wait "$child" 2>/dev/null || true
  rm -f "$pid_file"
}
trap cleanup EXIT HUP INT TERM
setsid /usr/bin/setpriv --regid "$OSCP_WORKSPACE_OWNER_GID" --clear-groups \
  .venv/bin/uvicorn app.main:app --app-dir backend \
  --host 127.0.0.1 --port 8000 --reload-include '*.yaml' "$@" &
child=$!
printf '%s\n' "$$" > "$pid_file"
chown "0:$OSCP_WORKSPACE_OWNER_GID" "$pid_file"
chmod 0664 "$pid_file"
wait "$child"
