import { configDefaults, defineConfig } from "vitest/config";

// frontend/e2e/*.spec.ts uses @playwright/test's own `test`/`expect`, not
// Vitest's -- without this exclude, `npm run test`'s default *.spec.ts
// glob would pick those files up too and fail (wrong test runner globals).
// Deliberately standalone (not merged with vite.config.ts): merging in the
// dev server's `plugins`/`server` config broke cross-file test isolation
// (a shared-state leak surfaced between unrelated test files at full-suite
// scale) even though nothing else about the setup needed it.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "e2e/**"],
  },
});
