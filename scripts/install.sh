#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/pip install -e "./backend[test]"
(cd frontend && npm install)
.venv/bin/python -m app.migrations
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/oscp-workspace" "${XDG_DATA_HOME:-$HOME/.local/share}/oscp-workspace" "${XDG_STATE_HOME:-$HOME/.local/state}/oscp-workspace" "$HOME/OSCP-Workspace/projects"
printf '%s\n' "Installed app dependencies." "Optional Kali tools: sudo apt install nmap gobuster feroxbuster enum4linux-ng"
