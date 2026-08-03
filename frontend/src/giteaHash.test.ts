import { describe, expect, it } from "vitest";
import { giteaHashToHashcatLine } from "./giteaHash";

function asciiToHex(value: string): string {
  return Array.from(value, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
}

describe("giteaHashToHashcatLine", () => {
  it("re-encodes hex passwd/salt columns into hashcat -m 10900's native line", () => {
    // "salt" and "hash" as ASCII, hex-encoded the way sqlite3 -> hex would show them
    const line = giteaHashToHashcatLine(asciiToHex("hash"), asciiToHex("salt"), "50000");
    expect(line).toBe(`sha256:50000:${btoa("salt")}:${btoa("hash")}`);
  });

  it("defaults to Gitea's standard iteration count of 50000", () => {
    const line = giteaHashToHashcatLine("aa", "bb");
    expect(line).toBe("sha256:50000:uw==:qg==");
  });

  it("returns undefined for invalid hex or missing fields", () => {
    expect(giteaHashToHashcatLine("not-hex", "bb")).toBeUndefined();
    expect(giteaHashToHashcatLine("", "bb")).toBeUndefined();
    expect(giteaHashToHashcatLine("aa", "")).toBeUndefined();
    expect(giteaHashToHashcatLine("abc", "bb")).toBeUndefined(); // odd-length hex
  });
});
