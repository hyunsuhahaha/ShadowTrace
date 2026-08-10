import { spawn, spawnSync, ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { E2E_BACKEND_PORT, E2E_FRONTEND_PORT } from "./ports";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../..");
const PYTHON = path.join(REPO_ROOT, ".venv/bin/python");
const BACKEND_URL = `http://127.0.0.1:${E2E_BACKEND_PORT}`;
export const SEED_FILE = path.join(__dirname, ".seed.json");

async function waitForReady(url: string, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function seed() {
  const project = await fetch(`${BACKEND_URL}/api/projects`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "E2E Golden Path", description: "" }),
  }).then((r) => r.json());

  const target = await fetch(`${BACKEND_URL}/api/targets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      project_id: project.id, name: "e2e-box", ip: "10.10.10.55",
    }),
  }).then((r) => r.json());

  // Published, ready-to-recommend runbook matching the service the fixture
  // XML declares (frontend/e2e/fixtures/scan.xml -> microsoft-ds/445), so
  // the spec sees a real recommendation card instead of an empty state.
  const template = await fetch(`${BACKEND_URL}/api/runbooks/templates`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: "E2E SMB basics", service_names: ["microsoft-ds"],
    }),
  }).then((r) => r.json());

  await fetch(`${BACKEND_URL}/api/runbooks/templates/${template.id}/publish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ steps: [{ title: "Check anonymous access" }] }),
  }).then((r) => r.json());

  return { project, target };
}

export default async function globalSetup() {
  const dataDir = mkdtempSync(path.join(tmpdir(), "oscp-e2e-"));
  const env = {
    ...process.env,
    OSCP_WORKSPACE_CONFIG: path.join(dataDir, "config"),
    OSCP_WORKSPACE_DATA: path.join(dataDir, "data"),
    OSCP_WORKSPACE_STATE: path.join(dataDir, "state"),
    OSCP_WORKSPACE_ROOT: path.join(dataDir, "root"),
    OSCP_WORKSPACE_DB: path.join(dataDir, "data", "workspace.db"),
  };

  // Non-root uvicorn only: main.py's loopback-only guard
  // (OSCP_ALLOW_ROOT/OSCP_BACKEND_BIND) exists specifically to stop a
  // privileged backend from ever binding beyond 127.0.0.1, and only fires
  // when geteuid()==0 — this process never touches that path, so the guard
  // stays fully intact for the real dev/production launchers.
  const migrate = spawnSync(PYTHON, ["-m", "app.migrations"], {
    cwd: path.join(REPO_ROOT, "backend"), env,
  });
  if (migrate.status !== 0) {
    throw new Error(`E2E migration failed:\n${migrate.stderr}`);
  }

  const backend: ChildProcess = spawn(
    PYTHON,
    ["-m", "uvicorn", "app.main:app", "--app-dir", "backend",
     "--host", "127.0.0.1", "--port", String(E2E_BACKEND_PORT)],
    { cwd: REPO_ROOT, env, detached: true, stdio: "ignore" },
  );
  await waitForReady(`http://127.0.0.1:${E2E_BACKEND_PORT}/api/system/status`, 20_000);

  const { project, target } = await seed();

  const frontend: ChildProcess = spawn(
    "npm", ["run", "dev", "--", "--port", String(E2E_FRONTEND_PORT), "--strictPort"],
    {
      cwd: path.join(REPO_ROOT, "frontend"),
      env: { ...env, VITE_API_TARGET: `http://127.0.0.1:${E2E_BACKEND_PORT}` },
      detached: true, stdio: "ignore",
    },
  );
  await waitForReady(`http://127.0.0.1:${E2E_FRONTEND_PORT}/`, 20_000);

  writeFileSync(SEED_FILE, JSON.stringify({
    projectId: project.id, targetId: target.id, targetIp: target.ip,
    targetName: target.name,
    backendPid: backend.pid, frontendPid: frontend.pid, dataDir,
  }));
}
