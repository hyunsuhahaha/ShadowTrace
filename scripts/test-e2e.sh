#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Separate from test.sh on purpose: this downloads a browser binary and
# spins up an isolated non-root backend + Vite dev server (see
# frontend/e2e/global-setup.ts), so it stays out of the normal fast
# pytest+build path.
(cd frontend && npx playwright install --with-deps chromium)
(cd frontend && npm run test:e2e)
