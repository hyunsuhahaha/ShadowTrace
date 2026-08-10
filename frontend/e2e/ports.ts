// Fixed, out-of-the-way ports for the isolated E2E stack (never 8000/5173,
// which the developer's own `scripts/dev.sh` instance normally occupies).
// Playwright resolves `playwright.config.ts` before `globalSetup` runs, so
// these can't be dynamically chosen there and then threaded into `use.baseURL`
// — both files import this module instead.
export const E2E_BACKEND_PORT = 8971;
export const E2E_FRONTEND_PORT = 5971;
export const E2E_BASE_URL = `http://127.0.0.1:${E2E_FRONTEND_PORT}`;
