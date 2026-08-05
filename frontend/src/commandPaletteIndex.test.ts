import { expect, it } from "vitest";
import { commandPaletteIndex, searchCommandPalette } from "./commandPaletteIndex";

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
