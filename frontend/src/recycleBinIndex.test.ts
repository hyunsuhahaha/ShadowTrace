import { describe, expect, it } from "vitest";
import { parseRecycleBinIndex } from "./recycleBinIndex";

const FILETIME_UNIX_EPOCH_DIFF_100NS = 116444736000000000n;

function buildIndexFile(
  { size, deletedAt, path }: { size: bigint; deletedAt: Date; path: string },
): string {
  const codeUnits = Array.from(path, (c) => c.charCodeAt(0));
  const buffer = new ArrayBuffer(28 + codeUnits.length * 2);
  const view = new DataView(buffer);
  view.setBigUint64(0, 2n, true);
  view.setBigInt64(8, size, true);
  const filetime = BigInt(deletedAt.getTime()) * 10000n + FILETIME_UNIX_EPOCH_DIFF_100NS;
  view.setBigUint64(16, filetime, true);
  view.setInt32(24, codeUnits.length, true);
  codeUnits.forEach((code, i) => view.setUint16(28 + i * 2, code, true));
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

describe("parseRecycleBinIndex", () => {
  it("parses size, deletion time, and original path from a Windows 10 $I file", () => {
    const deletedAt = new Date("2020-01-01T00:00:00.000Z");
    const base64 = buildIndexFile({ size: 31_457_280n, deletedAt, path: "C:\\IT\\backup.7z" });

    const result = parseRecycleBinIndex(base64);
    expect(result).toBeTruthy();
    expect(result?.originalSize).toBe(31_457_280n);
    expect(result?.originalPath).toBe("C:\\IT\\backup.7z");
    expect(result?.deletedAt.toISOString()).toBe("2020-01-01T00:00:00.000Z");
  });

  it("returns undefined for empty input", () => {
    expect(parseRecycleBinIndex("")).toBeUndefined();
    expect(parseRecycleBinIndex("   ")).toBeUndefined();
  });

  it("returns undefined for input too short to be a valid header", () => {
    expect(parseRecycleBinIndex(btoa("short"))).toBeUndefined();
  });

  it("returns undefined for a non-Windows-10 version (e.g. Vista/7's format 1)", () => {
    const buffer = new ArrayBuffer(28);
    new DataView(buffer).setBigUint64(0, 1n, true);
    const bytes = new Uint8Array(buffer);
    let binary = "";
    bytes.forEach((b) => { binary += String.fromCharCode(b); });
    expect(parseRecycleBinIndex(btoa(binary))).toBeUndefined();
  });

  it("returns undefined for malformed base64", () => {
    expect(parseRecycleBinIndex("not valid base64 at all !!!")).toBeUndefined();
  });
});
