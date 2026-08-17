// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { selectInitialScanTarget, selectVisibleScan, serverTime, syncSelectedProject,
  type Scan } from "./scanCenterModel";

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

describe("scan selection", () => {
  const scan = (id: number) => ({id} as Scan);

  it("does not overwrite a newly-created scan while the query cache is stale", () => {
    expect(selectVisibleScan(26, [scan(25), scan(24)])).toBe(26);
  });

  it("selects the newest visible scan only when nothing is selected", () => {
    expect(selectVisibleScan(undefined, [scan(25), scan(24)])).toBe(25);
  });
});

describe("scan target restoration", () => {
  it("keeps the graph host instead of restoring a docked target from another project", () => {
    expect(selectInitialScanTarget(18, 19, {targetId: 17, projectId: 18})).toBe(18);
  });

  it("restores a docked target only inside its own project", () => {
    expect(selectInitialScanTarget(undefined, 19, {targetId: 18, projectId: 19})).toBe(18);
    expect(selectInitialScanTarget(undefined, 19, {targetId: 17, projectId: 18})).toBeUndefined();
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
