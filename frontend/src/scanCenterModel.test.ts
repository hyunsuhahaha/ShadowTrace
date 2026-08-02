// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { serverTime, syncSelectedProject } from "./scanCenterModel";

describe("scan timestamps", () => {
  it("treats SQLite timestamps without an offset as UTC", () => {
    expect(serverTime("2026-07-30T05:55:00")).toBe(
      Date.parse("2026-07-30T05:55:00Z"),
    );
    expect(serverTime("2026-07-30T01:55:00-04:00")).toBe(
      Date.parse("2026-07-30T01:55:00-04:00"),
    );
  });
});

describe("project selection synchronization", () => {
  it("emits a project change only when the selected project actually changes", () => {
    localStorage.clear();
    let changes = 0;
    const listener = () => changes++;
    addEventListener("oscp-project-change", listener);

    expect(syncSelectedProject(1)).toBe(true);
    expect(syncSelectedProject(1)).toBe(false);
    expect(changes).toBe(1);

    removeEventListener("oscp-project-change", listener);
    localStorage.clear();
  });
});
