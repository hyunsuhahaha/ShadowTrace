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
    expect(ids).toContain("mysql-outfile-webshell");
    expect(ids).toContain("mysql-udf-rce");
  });

  it("gives the PostgreSQL COPY FROM PROGRAM entry an injection-context payload", () => {
    const category = findSqlPayloadCategory("postgres-copy-program");
    expect(category?.engines).toEqual(["postgresql"]);
    const stacked = category?.payloads.find((item) => item.payload.startsWith("';"));
    expect(stacked?.payload).toContain("COPY cmd_exec FROM PROGRAM");
    expect(stacked?.payload).toContain("--");
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
