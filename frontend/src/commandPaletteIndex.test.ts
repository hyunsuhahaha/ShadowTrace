import { expect, it } from "vitest";
import { commandPaletteIndex, matchesServiceKind, searchCommandPalette } from "./commandPaletteIndex";

const service = (overrides: Partial<Parameters<typeof matchesServiceKind>[0]> = {}) => ({
  id: 1, target_id: 1, port: 80, protocol: "tcp", name: "http", product: "", scripts: "",
  ...overrides,
});

it("has a unique id and a valid route for every entry", () => {
  const ids = commandPaletteIndex.map((entry) => entry.id);
  expect(new Set(ids).size).toBe(ids.length);
  commandPaletteIndex.forEach((entry) => {
    expect(entry.route).toBeTruthy();
    if (entry.subroute) expect(entry.id).toBe(`${entry.route}/${entry.subroute}`);
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

it("every anchored (service-scoped) entry declares a serviceKind", () => {
  commandPaletteIndex.filter((entry) => entry.anchorId).forEach((entry) => {
    expect(entry.serviceKind, entry.id).toBeTruthy();
  });
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
