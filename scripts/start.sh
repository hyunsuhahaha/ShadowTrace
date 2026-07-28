#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" -eq 0 ]; then echo "Do not run OSCP Workspace as root."; exit 1; fi
.venv/bin/python -m app.migrations
exec .venv/bin/uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
