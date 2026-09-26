// @vitest-environment jsdom
import {afterEach, expect, it, vi} from "vitest";

afterEach(() => {
  sessionStorage.clear();
  location.hash = "";
  vi.resetModules();
});

it("keeps a saved Evidence deep link on a fresh browser session", async () => {
  sessionStorage.clear();
  location.hash = "#evidence/2/10";
  vi.resetModules();

  await import("./Root");

  expect(location.hash).toBe("#evidence/2/10");
  expect(sessionStorage.getItem("oscp-home-shown")).toBe("1");
});

it("still opens the graph for a restored workspace hash", async () => {
  sessionStorage.clear();
  location.hash = "#scans";
  vi.resetModules();

  await import("./Root");

  expect(location.hash).toBe("#graph");
});
