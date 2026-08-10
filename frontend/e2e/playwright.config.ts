import { defineConfig, devices } from "@playwright/test";
import { E2E_BASE_URL } from "./ports";

// No built-in `webServer` here on purpose: golden-path.spec.ts needs a
// non-root backend on an isolated OSCP_WORKSPACE_* data dir (never the
// user's real workspace), which global-setup/global-teardown manage
// explicitly so cleanup is guaranteed even if a run is interrupted.
export default defineConfig({
  testDir: ".",
  timeout: 90_000,
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  use: {
    baseURL: E2E_BASE_URL,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
