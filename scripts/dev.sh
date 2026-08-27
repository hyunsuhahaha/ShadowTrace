#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" -eq 0 ]; then
  echo "Run dev.sh as the regular desktop user, not root." >&2
  exit 1
fi
state_dir="${OSCP_WORKSPACE_STATE:-$HOME/.local/state/oscp-workspace}"
.venv/bin/pip install -q -e ./backend
if .venv/bin/python -c \
  'import socket; socket.create_connection(("127.0.0.1", 8000), timeout=0.3).close()' \
  >/dev/null 2>&1; then
  existing="$(pgrep -f 'uvicorn app.main:app.*--port 8000' | paste -sd, - || true)"
  echo "A ShadowTrace backend is already using 127.0.0.1:8000${existing:+ (PID $existing)}." >&2
  echo "Stop the previous dev server first; if it was started with sudo, run:" >&2
  echo "  sudo pkill -TERM -f 'scripts/start.sh'" >&2
  echo "Then run ./scripts/dev.sh again." >&2
  exit 1
fi
sudo -v
./scripts/start.sh --reload &
backend=$!
cleanup() {
  trap - EXIT INT TERM
  pid_file="$state_dir/root-backend.pid"
  if [ -r "$pid_file" ]; then
    root_backend="$(cat "$pid_file")"
    case "$root_backend" in
      *[!0-9]*|"") ;;
      *) sudo -n kill -TERM "$root_backend" 2>/dev/null || true ;;
    esac
    for _ in $(seq 1 50); do
      [ -e "$pid_file" ] || break
      sleep 0.1
    done
  fi
  kill -TERM "$backend" 2>/dev/null || true
  wait "$backend" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

backend_ready=""
for _ in $(seq 1 100); do
  if .venv/bin/python -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/api/system/status", timeout=0.2).read()' \
    >/dev/null 2>&1; then
    backend_ready=1
    break
  fi
  if ! kill -0 "$backend" 2>/dev/null; then
    echo "FastAPI backend exited before it became ready." >&2
    wait "$backend"
    exit 1
  fi
  sleep 0.1
done
if [ -z "$backend_ready" ]; then
  echo "FastAPI backend did not become ready within 10 seconds." >&2
  exit 1
fi

(cd frontend && npm run dev)
