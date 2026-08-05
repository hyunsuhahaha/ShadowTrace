import { expect, it } from "vitest";
import { commandPaletteIndex, searchCommandPalette } from "./commandPaletteIndex";

it("has a unique id and a valid route/subroute pair for every entry", () => {
  const ids = commandPaletteIndex.map((entry) => entry.id);
  expect(new Set(ids).size).toBe(ids.length);
  commandPaletteIndex.forEach((entry) => {
    expect(entry.route).toBeTruthy();
    expect(entry.id).toBe(entry.subroute ? `${entry.route}/${entry.subroute}` : entry.route);
  });
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
