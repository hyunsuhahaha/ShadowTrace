import { describe, expect, it } from "vitest";
import { decodeCiscoType7 } from "./ciscoType7";

describe("decodeCiscoType7", () => {
  it("decodes real Cisco IOS type 7 passwords (verified against known plaintexts)", () => {
    expect(decodeCiscoType7("0242114B0E143F015F5D1E161713")).toBe("$uperP@ssword");
    expect(decodeCiscoType7("02375012182C1A1D751618034F36415408")).toBe("Q4)sJu\\Y8qz*A3?d");
  });

  it("trims surrounding whitespace before decoding", () => {
    expect(decodeCiscoType7("  0242114B0E143F015F5D1E161713  ")).toBe("$uperP@ssword");
  });

  it("returns undefined for input that isn't seed+hex", () => {
    expect(decodeCiscoType7("not-hex-at-all")).toBeUndefined();
    expect(decodeCiscoType7("")).toBeUndefined();
    expect(decodeCiscoType7("02ABC")).toBeUndefined(); // odd-length hex body
  });

  it("returns undefined when the seed is out of the key table's range", () => {
    expect(decodeCiscoType7("99AABBCC")).toBeUndefined();
  });
});
