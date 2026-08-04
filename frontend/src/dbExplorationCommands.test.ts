import { describe, expect, it } from "vitest";
import { getDbExplorationGuide } from "./dbExplorationCommands";

describe("DB exploration command reference", () => {
  it("gives every listed engine a non-empty, labeled command list", () => {
    for (const service of ["mysql", "ms-sql-s", "postgresql", "redis", "mongodb"]) {
      const guide = getDbExplorationGuide(service);
      expect(guide?.commands.length).toBeGreaterThan(0);
      for (const item of guide!.commands) {
        expect(item.label.length).toBeGreaterThan(0);
        expect(item.command.length).toBeGreaterThan(0);
      }
    }
  });

  it("looks up case-insensitively and returns undefined for an unknown service", () => {
    expect(getDbExplorationGuide("MySQL")?.title).toBe("MySQL 탐색 명령");
    expect(getDbExplorationGuide("ftp")).toBeUndefined();
    expect(getDbExplorationGuide()).toBeUndefined();
  });
});
