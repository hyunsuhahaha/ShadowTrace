import { expect, it } from "vitest";
import { commandPaletteIndex, matchesServiceKind, searchCommandPalette } from "./commandPaletteIndex";

const service = (overrides: Partial<Parameters<typeof matchesServiceKind>[0]> = {}) => ({
  id: 1, target_id: 1, port: 80, protocol: "tcp", name: "http", product: "", scripts: "",
  ...overrides,
});

it("has a unique id and a valid route for every entry", () => {
  const ids = commandPaletteIndex.map((entry) => entry.id);
  expect(new Set(ids).size).toBe(ids.length);
  const bySubroute = new Map<string, number>();
  commandPaletteIndex.forEach((entry) => {
    if (!entry.subroute) return;
    const key = `${entry.route}/${entry.subroute}`;
    bySubroute.set(key, (bySubroute.get(key) || 0) + 1);
  });
  commandPaletteIndex.forEach((entry) => {
    expect(entry.route).toBeTruthy();
    if (!entry.subroute) return;
    const key = `${entry.route}/${entry.subroute}`;
    // A subroute reached by exactly one entry keeps id === route/subroute
    // (recent-items tracking keys off this elsewhere). Several entries can
    // anchor into the same subroute (e.g. each DB engine's payload
    // reference, all under #web/sqli): the canonical page entry still uses
    // the bare key, and every other one prefixes its own id with it.
    if (bySubroute.get(key) === 1) expect(entry.id).toBe(key);
    else expect(entry.id === key || entry.id.startsWith(`${key}-`), entry.id).toBe(true);
  });
});

it("finds the directory-fuzzing panel by its gobuster alias even though the app uses feroxbuster", () => {
  const results = searchCommandPalette("gobuster");
  expect(results.map((entry) => entry.id)).toContain("enumeration/dir-fuzz");
});

it("finds the vhost-fuzzing panel by gobuster's vhost mode name", () => {
  const results = searchCommandPalette("gobuster vhost");
  expect(results.map((entry) => entry.id)).toContain("enumeration/vhost-fuzz");
});

it("finds the real DNS subdomain brute-forcer by gobuster's dns mode name", () => {
  const results = searchCommandPalette("gobuster dns");
  expect(results.map((entry) => entry.id)).toContain("enumeration/dns-subdomain");
  expect(results.map((entry) => entry.id)).not.toContain("enumeration/vhost-fuzz");
});

it("finds the SQLi reference tab by its English security term, not just its Korean label", () => {
  const results = searchCommandPalette("sql injection");
  expect(results.map((entry) => entry.id)).toContain("web/sqli");
});

it("finds the reverse-shell panel by its English name", () => {
  const results = searchCommandPalette("reverse shell");
  expect(results.map((entry) => entry.id)).toContain("enumeration/reverse-shell");
});

it("finds the Repeater tab by its Burp-style alias even though the tab itself is labeled Request", () => {
  const results = searchCommandPalette("repeater");
  expect(results.map((entry) => entry.id)).toContain("web/request");
});

it("finds Operations by a Korean keyword that never appears in its English label", () => {
  const results = searchCommandPalette("백업");
  expect(results.map((entry) => entry.id)).toContain("operations");
});

it("matches case-insensitively", () => {
  expect(searchCommandPalette("LOG4SHELL").map((entry) => entry.id)).toContain("web/log4shell");
});

it("returns nothing for an empty or whitespace-only query", () => {
  expect(searchCommandPalette("")).toEqual([]);
  expect(searchCommandPalette("   ")).toEqual([]);
});

it("returns nothing for a query that matches no entry", () => {
  expect(searchCommandPalette("xyzzyquux")).toEqual([]);
});

it("every anchor into a service-conditional panel declares a serviceKind", () => {
  // Service Enumeration's fuzz/etc. panels only render once a matching
  // service is selected, so their entries need serviceKind to offer a
  // picker when the anchor isn't there yet. An anchor into a static,
  // always-rendered reference page (e.g. a SQLi payload category, no
  // service dependency at all) legitimately has none -- see the
  // CommandPaletteEntry.serviceKind comment.
  commandPaletteIndex
    .filter((entry) => entry.anchorId && entry.category === "Service Enumeration 도구")
    .forEach((entry) => {
      expect(entry.serviceKind, entry.id).toBeTruthy();
    });
});

it("finds each DB engine's payload reference by name, deep-linked to its own category", () => {
  for (const [query, id, anchor] of [
    ["postgre", "web/sqli-postgres", "sqlpayload-postgres-basics"],
    ["mysql", "web/sqli-mysql", "sqlpayload-mysql-basics"],
    ["mssql", "web/sqli-mssql", "sqlpayload-mssql-basics"],
    ["redis", "web/sqli-redis", "sqlpayload-redis-basics"],
    ["mongodb", "web/sqli-mongodb", "sqlpayload-mongodb-basics"],
  ] as const) {
    const results = searchCommandPalette(query);
    const entry = results.find((item) => item.id === id);
    expect(entry, `${query} -> ${id}`).toBeTruthy();
    expect(entry?.anchorId).toBe(anchor);
    expect(entry?.serviceKind).toBeUndefined();
  }
});

it("finds the LinPEAS analysis panel by name, deep-linked into Post-Exploitation", () => {
  for (const query of ["linpeas", "권한 상승 스캔"]) {
    const results = searchCommandPalette(query);
    const entry = results.find((item) => item.id === "post-exploitation/linpeas");
    expect(entry, query).toBeTruthy();
    expect(entry?.route).toBe("post-exploitation");
    expect(entry?.subroute).toBeUndefined();
    expect(entry?.anchorId).toBe("linpeas-heading");
    expect(entry?.serviceKind).toBeUndefined();
  }
});

it("finds the restricted-shell reference by an ls/cat-not-working style query, deep-linked into Post-Exploitation", () => {
  for (const query of ["rbash", "busybox", "noexec", "ls 안됨"]) {
    const results = searchCommandPalette(query);
    const entry = results.find((item) => item.id === "post-exploitation/restricted-shell");
    expect(entry, query).toBeTruthy();
    expect(entry?.route).toBe("post-exploitation");
    expect(entry?.subroute).toBeUndefined();
    expect(entry?.anchorId).toBe("privesc-restricted-shell");
    expect(entry?.serviceKind).toBeUndefined();
  }
});

it("finds the per-distro service config path reference by pg_hba.conf, the thing that started this whole checklist", () => {
  for (const query of ["pg_hba.conf", "설정 파일 위치", "smb.conf", "my.cnf"]) {
    const results = searchCommandPalette(query);
    const entry = results.find((item) => item.id === "post-exploitation/config-paths");
    expect(entry, query).toBeTruthy();
    expect(entry?.route).toBe("post-exploitation");
    expect(entry?.anchorId).toBe("privesc-config-paths");
  }
});

it("makes every linuxPrivescCommands category individually findable, not just the newest one", () => {
  const categoryEntries = commandPaletteIndex.filter((entry) =>
    entry.route === "post-exploitation" && entry.anchorId?.startsWith("privesc-"));
  expect(categoryEntries.map((entry) => entry.anchorId).sort()).toEqual([
    "privesc-basic-info", "privesc-config-paths", "privesc-cron-services",
    "privesc-restricted-shell", "privesc-suid-cap", "privesc-writable-shell",
  ]);
});

it("matchesServiceKind treats plain http/https services as http, not dns", () => {
  expect(matchesServiceKind(service({ name: "http" }), "http")).toBe(true);
  expect(matchesServiceKind(service({ name: "https" }), "http")).toBe(true);
  expect(matchesServiceKind(service({ name: "http" }), "dns")).toBe(false);
});

it("matchesServiceKind excludes WinRM's HTTPAPI false-positive from http", () => {
  expect(matchesServiceKind(
    service({ name: "http", port: 5985, product: "Microsoft HTTPAPI httpd 2.0" }), "http",
  )).toBe(false);
});

it("matchesServiceKind treats domain/dns services as dns", () => {
  expect(matchesServiceKind(service({ name: "domain" }), "dns")).toBe(true);
  expect(matchesServiceKind(service({ name: "domain" }), "http")).toBe(false);
});
