import { describe, expect, it } from "vitest";
import { findSqlPayloadCategory, sqlPayloadCategories } from "./sqlPayloads";

describe("manual SQLi payload catalog", () => {
  it("has unique, non-empty category ids", () => {
    const ids = sqlPayloadCategories.map((category) => category.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.every(Boolean)).toBe(true);
  });

  it("gives every payload a label and a non-empty payload string", () => {
    for (const category of sqlPayloadCategories) {
      expect(category.payloads.length).toBeGreaterThan(0);
      for (const item of category.payloads) {
        expect(item.label.length).toBeGreaterThan(0);
        expect(item.payload.length).toBeGreaterThan(0);
      }
    }
  });

  it("covers manual SQLi and DB-specific RCE, since SQLmap is exam-banned", () => {
    const ids = sqlPayloadCategories.map((category) => category.id);
    expect(ids).toContain("union");
    expect(ids).toContain("boolean-blind");
    expect(ids).toContain("time-blind");
    expect(ids).toContain("mssql-xp-cmdshell");
    expect(ids).toContain("postgres-copy-program");
  });

  it("gives the PostgreSQL COPY FROM PROGRAM entry an injection-context payload", () => {
    const category = findSqlPayloadCategory("postgres-copy-program");
    expect(category?.engines).toEqual(["postgresql"]);
    const stacked = category?.payloads.find((item) => item.payload.startsWith("';"));
    expect(stacked?.payload).toContain("COPY cmd_exec FROM PROGRAM");
    expect(stacked?.payload).toContain("--");
  });

  it("looks up a category by id", () => {
    expect(findSqlPayloadCategory("union")?.title).toBe("UNION 기반 추출");
    expect(findSqlPayloadCategory("does-not-exist")).toBeUndefined();
  });
});
