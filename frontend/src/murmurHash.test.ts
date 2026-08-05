import { describe, expect, it } from "vitest";
import { murmurHash3_32, shodanFaviconHash } from "./murmurHash";

const utf8 = (s: string) => new TextEncoder().encode(s);

describe("murmurHash3_32", () => {
  // Every value below was cross-checked against Python's mmh3.hash() (the
  // reference implementation Shodan/censys and every favicon-hash.py clone
  // build on), not just derived from this same code.
  it("matches mmh3.hash() across empty, sub-block, and exact-block lengths", () => {
    expect(murmurHash3_32(utf8(""))).toBe(0);
    expect(murmurHash3_32(utf8("a"))).toBe(1009084850);
    expect(murmurHash3_32(utf8("ab"))).toBe(-1681926305);
    expect(murmurHash3_32(utf8("abc"))).toBe(-1277324294);
    expect(murmurHash3_32(utf8("abcd"))).toBe(1139631978);
    expect(murmurHash3_32(utf8("hello"))).toBe(613153351);
  });

  it("matches mmh3.hash() for longer text and full-range binary input", () => {
    expect(murmurHash3_32(utf8("The quick brown fox jumps over the lazy dog")))
      .toBe(776992547);
    const binary = new Uint8Array(256);
    for (let i = 0; i < 256; i++) binary[i] = i;
    expect(murmurHash3_32(binary)).toBe(-469103018);
  });
});

describe("shodanFaviconHash", () => {
  // Cross-checked against Python's
  // mmh3.hash(codecs.encode(data, "base64")) -- the exact pipeline Shodan's
  // http.favicon.hash and censys use.
  it("matches the reference base64-MIME-wrap-then-hash pipeline", () => {
    expect(shodanFaviconHash(new Uint8Array())).toBe(0);
    expect(shodanFaviconHash(new Uint8Array([1, 2, 3, 4, 5]))).toBe(-362770216);
    const repeating = new Uint8Array(768);
    for (let i = 0; i < 768; i++) repeating[i] = i % 256;
    expect(shodanFaviconHash(repeating)).toBe(1836528006);
  });
});
