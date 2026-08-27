#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then
  owner_uid="$(id -u)"
  owner_gid="$(id -g)"
  owner_home="$HOME"
  export OSCP_WORKSPACE_CONFIG="${OSCP_WORKSPACE_CONFIG:-$owner_home/.config/oscp-workspace}"
  export OSCP_WORKSPACE_DATA="${OSCP_WORKSPACE_DATA:-$owner_home/.local/share/oscp-workspace}"
  export OSCP_WORKSPACE_STATE="${OSCP_WORKSPACE_STATE:-$owner_home/.local/state/oscp-workspace}"
  export OSCP_WORKSPACE_ROOT="${OSCP_WORKSPACE_ROOT:-$owner_home/OSCP-Workspace}"
  export OSCP_WORKSPACE_DB="${OSCP_WORKSPACE_DB:-$OSCP_WORKSPACE_DATA/workspace.db}"
  export OSCP_WORKSPACE_OWNER_UID="$owner_uid"
  export OSCP_WORKSPACE_OWNER_GID="$owner_gid"
  export OSCP_WORKSPACE_OWNER_HOME="$owner_home"
  mkdir -p "$OSCP_WORKSPACE_CONFIG" "$OSCP_WORKSPACE_DATA" \
    "$OSCP_WORKSPACE_STATE" "$OSCP_WORKSPACE_ROOT"
  .venv/bin/python -m app.migrations
  sudo -v
  exec sudo --preserve-env=OSCP_WORKSPACE_CONFIG,OSCP_WORKSPACE_DATA,OSCP_WORKSPACE_STATE,OSCP_WORKSPACE_ROOT,OSCP_WORKSPACE_DB,OSCP_WORKSPACE_OWNER_UID,OSCP_WORKSPACE_OWNER_GID,OSCP_WORKSPACE_OWNER_HOME \
    "$0" "$@"
fi

: "${OSCP_WORKSPACE_OWNER_GID:?missing owner gid}"
: "${OSCP_WORKSPACE_OWNER_UID:?missing owner uid}"
: "${OSCP_WORKSPACE_CONFIG:?missing config path}"
: "${OSCP_WORKSPACE_DATA:?missing data path}"
: "${OSCP_WORKSPACE_STATE:?missing state path}"
: "${OSCP_WORKSPACE_ROOT:?missing workspace path}"
umask 0002
export OSCP_ALLOW_ROOT=1 OSCP_BACKEND_BIND=127.0.0.1 PYTHONDONTWRITEBYTECODE=1
export PATH="${OSCP_WORKSPACE_OWNER_HOME:+$OSCP_WORKSPACE_OWNER_HOME/.local/bin:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

child=""
observer=""
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
  if [ -n "$observer" ] && kill -0 "$observer" 2>/dev/null; then
    kill -TERM "$observer" 2>/dev/null || true
  fi
  wait "$observer" 2>/dev/null || true
  wait "$child" 2>/dev/null || true
  rm -f "$pid_file"
}
trap cleanup EXIT HUP INT TERM

if /usr/bin/python3 -c 'import bcc' >/dev/null 2>&1; then
  /usr/bin/python3 scripts/passive-observer.py &
  observer=$!
else
  echo "Passive observer disabled: install python3-bpfcc." >&2
fi
setsid /usr/bin/setpriv --regid "$OSCP_WORKSPACE_OWNER_GID" --clear-groups \
  .venv/bin/uvicorn app.main:app --app-dir backend \
  --host 127.0.0.1 --port 8000 --reload-include '*.yaml' "$@" &
child=$!
printf '%s\n' "$$" > "$pid_file"
chown "0:$OSCP_WORKSPACE_OWNER_GID" "$pid_file"
chmod 0664 "$pid_file"
wait "$child"
