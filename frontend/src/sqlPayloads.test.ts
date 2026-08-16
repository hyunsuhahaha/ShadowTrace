import { describe, expect, it } from "vitest";
import { dbRceCategoriesFor, findSqlPayloadCategory, sqlPayloadCategories } from "./sqlPayloads";

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
    expect(ids).toContain("mysql-outfile-webshell");
    expect(ids).toContain("mysql-udf-rce");
  });

  it("gives the PostgreSQL COPY FROM PROGRAM entry both a direct and an injection-context reverse shell", () => {
    const category = findSqlPayloadCategory("postgres-copy-program");
    expect(category?.engines).toEqual(["postgresql"]);
    const stacked = category?.payloads.find((item) => item.payload.startsWith("';"));
    expect(stacked?.payload).toContain("COPY cmd_exec FROM PROGRAM");
    expect(stacked?.payload).toContain("--");
    expect(stacked?.context).toBe("injection");
    const direct = category?.payloads.find((item) =>
      item.context === "direct" && item.payload.includes("nc {LHOST} {LPORT}"));
    expect(direct).toBeTruthy();
    expect(direct?.payload.startsWith("'")).toBe(false);
  });

  it("gives MSSQL xp_cmdshell a reverse-shell payload whose SQL string literal is well-formed", () => {
    const category = findSqlPayloadCategory("mssql-xp-cmdshell");
    expect(category?.engines).toEqual(["mssql"]);
    const revshell = category?.payloads.find((item) => item.label.startsWith("리버스 쉘")
      && !item.payload.startsWith("';"));
    expect(revshell?.payload).toContain("{LHOST}");
    expect(revshell?.payload).toContain("{LPORT}");
    // xp_cmdshell's own argument is a single-quoted SQL string -- every inner
    // quote must be an escaped double-quote (\"), never a bare single quote,
    // or the payload would terminate that string early and break the command.
    const inner = revshell!.payload.slice(
      revshell!.payload.indexOf("xp_cmdshell '") + "xp_cmdshell '".length,
      revshell!.payload.lastIndexOf("'"),
    );
    expect(inner).not.toContain("'");
    const stacked = category?.payloads.find((item) => item.label.startsWith("리버스 쉘")
      && item.payload.startsWith("';"));
    expect(stacked?.payload).toContain("{LHOST}");
    expect(stacked?.payload).toContain("{LPORT}");
  });

  it("has both a MySQL OUTFILE webshell path and a UDF path, each ending in a reverse shell", () => {
    const outfile = findSqlPayloadCategory("mysql-outfile-webshell");
    expect(outfile?.engines).toEqual(["mysql"]);
    expect(outfile?.payloads.some((item) => item.payload.includes("INTO OUTFILE"))).toBe(true);
    const trigger = outfile?.payloads.find((item) => item.payload.includes("{LHOST}"));
    expect(trigger?.payload).toContain("{LPORT}");

    const udf = findSqlPayloadCategory("mysql-udf-rce");
    expect(udf?.engines).toEqual(["mysql"]);
    expect(udf?.payloads.some((item) => item.payload.includes("sys_exec"))).toBe(true);
    const udfShell = udf?.payloads.find((item) => item.payload.includes("{LHOST}"));
    expect(udfShell?.payload).toContain("{LPORT}");
  });

  it("looks up a category by id", () => {
    expect(findSqlPayloadCategory("union")?.title).toBe("UNION 기반 추출");
    expect(findSqlPayloadCategory("does-not-exist")).toBeUndefined();
  });
});

describe("dbRceCategoriesFor", () => {
  it("maps each DB engine's nmap service name to its own RCE categories only", () => {
    expect(dbRceCategoriesFor("postgresql").map((c) => c.id)).toEqual(["postgres-copy-program"]);
    expect(dbRceCategoriesFor("mysql").map((c) => c.id))
      .toEqual(["mysql-outfile-webshell", "mysql-udf-rce"]);
    expect(dbRceCategoriesFor("ms-sql-s").map((c) => c.id)).toEqual(["mssql-xp-cmdshell"]);
  });

  it("matches case-insensitively, same as nmap service strings can vary", () => {
    expect(dbRceCategoriesFor("MySQL").map((c) => c.id)).toEqual(["mysql-outfile-webshell", "mysql-udf-rce"]);
  });

  it("returns nothing for a service with no DB RCE reference (ssh, redis, http, ...)", () => {
    expect(dbRceCategoriesFor("ssh")).toEqual([]);
    expect(dbRceCategoriesFor("redis")).toEqual([]);
    expect(dbRceCategoriesFor("http")).toEqual([]);
  });

  it("drops every injection-context payload, keeping only the ones safe to paste directly into an authenticated client", () => {
    for (const serviceName of ["postgresql", "mysql", "ms-sql-s"]) {
      for (const category of dbRceCategoriesFor(serviceName)) {
        expect(category.payloads.every((item) => item.context !== "injection")).toBe(true);
        expect(category.payloads.length).toBeGreaterThan(0);
      }
    }
  });

  it("does not mutate the underlying catalog when filtering", () => {
    dbRceCategoriesFor("mysql");
    const original = findSqlPayloadCategory("mysql-outfile-webshell");
    expect(original?.payloads.some((item) => item.context === "injection")).toBe(true);
  });
});
