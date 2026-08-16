// @vitest-environment jsdom
import { expect, it } from "vitest";
import { buildNoneAlgJwt } from "./jwtForge";

function b64urlDecode(segment: string): string {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/")
    .padEnd(segment.length + (4 - segment.length % 4) % 4, "=");
  return atob(padded);
}

it("builds a three-part token with an empty signature", () => {
  const token = buildNoneAlgJwt('{"alg":"none","typ":"JWT"}', '{"sub":"attacker","role":"admin"}');
  const parts = token.split(".");
  expect(parts).toHaveLength(3);
  expect(parts[2]).toBe("");
});

it("round-trips the header and payload through base64url so a real JWT parser reads them back unchanged", () => {
  const token = buildNoneAlgJwt('{"alg":"none","typ":"JWT"}', '{"sub":"attacker","role":"admin"}');
  const [header, payload] = token.split(".");
  expect(JSON.parse(b64urlDecode(header))).toEqual({ alg: "none", typ: "JWT" });
  expect(JSON.parse(b64urlDecode(payload))).toEqual({ sub: "attacker", role: "admin" });
});

it("throws on invalid JSON instead of silently building a broken token", () => {
  expect(() => buildNoneAlgJwt("{not json", "{}")).toThrow();
});
