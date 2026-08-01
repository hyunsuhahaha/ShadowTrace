#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" -eq 0 ]; then echo "Do not run OSCP Workspace as root."; exit 1; fi
owner_gid="$(id -g)"
owner_home="$HOME"
export OSCP_WORKSPACE_CONFIG="${OSCP_WORKSPACE_CONFIG:-$owner_home/.config/oscp-workspace}"
export OSCP_WORKSPACE_DATA="${OSCP_WORKSPACE_DATA:-$owner_home/.local/share/oscp-workspace}"
export OSCP_WORKSPACE_STATE="${OSCP_WORKSPACE_STATE:-$owner_home/.local/state/oscp-workspace}"
export OSCP_WORKSPACE_ROOT="${OSCP_WORKSPACE_ROOT:-$owner_home/OSCP-Workspace}"
export OSCP_WORKSPACE_DB="${OSCP_WORKSPACE_DB:-$OSCP_WORKSPACE_DATA/workspace.db}"
export OSCP_WORKSPACE_OWNER_GID="$owner_gid"
mkdir -p "$OSCP_WORKSPACE_CONFIG" "$OSCP_WORKSPACE_DATA" \
  "$OSCP_WORKSPACE_STATE" "$OSCP_WORKSPACE_ROOT"
.venv/bin/python -m app.migrations
sudo -v
exec sudo --preserve-env=OSCP_WORKSPACE_CONFIG,OSCP_WORKSPACE_DATA,OSCP_WORKSPACE_STATE,OSCP_WORKSPACE_ROOT,OSCP_WORKSPACE_DB,OSCP_WORKSPACE_OWNER_GID \
  ./scripts/run-root-backend.sh
