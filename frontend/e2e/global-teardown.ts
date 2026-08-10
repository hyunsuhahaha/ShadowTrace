import { existsSync, readFileSync, rmSync, unlinkSync } from "node:fs";
import { SEED_FILE } from "./global-setup";

export default async function globalTeardown() {
  if (!existsSync(SEED_FILE)) return;
  const { backendPid, frontendPid, dataDir } = JSON.parse(readFileSync(SEED_FILE, "utf-8"));
  // Negative pid = whole process group (both were spawned with
  // detached:true), so npm's spawned vite child dies with it too.
  for (const pid of [backendPid, frontendPid]) {
    try { process.kill(-pid, "SIGTERM"); } catch { /* already gone */ }
  }
  rmSync(dataDir, { recursive: true, force: true });
  unlinkSync(SEED_FILE);
}
