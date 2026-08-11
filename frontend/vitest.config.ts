import { configDefaults, defineConfig } from "vitest/config";

// frontend/e2e/*.spec.ts uses @playwright/test's own `test`/`expect`, not
// Vitest's -- without this exclude, `npm run test`'s default *.spec.ts
// glob would pick those files up too and fail (wrong test runner globals).
// Deliberately standalone (not merged with vite.config.ts): merging in the
// dev server's `plugins`/`server` config broke cross-file test isolation
// (a shared-state leak surfaced between unrelated test files at full-suite
// scale) even though nothing else about the setup needed it.
//
// `pool: "forks"` runs each test file in its own OS process instead of a
// shared worker thread. Vitest's default thread pool was letting jsdom's
// `document`/`window`/`localStorage` bleed across unrelated test files at
// full-suite scale -- confirmed twice independently (once via this file's
// merge above, once when an unrelated AppShell.tsx timing change flipped a
// WebWorkspace test that has nothing to do with AppShell). Forks are
// slower but this class of flake is worse than the cost.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "e2e/**"],
    pool: "forks",
  },
});
