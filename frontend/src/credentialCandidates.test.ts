import { describe, expect, it } from "vitest";
import { parseCandidates, previewCombinations, processCandidate, requestCount } from "./credentialCandidates";

const positions = [
  { name: "username", candidates: ["alice", "bob"] },
  { name: "password", candidates: ["one", "two", "three"] },
];

describe("credential candidates", () => {
  it("cleans input without sorting and optionally removes duplicates", () => {
    expect(parseCandidates(" bob,\nalice\nbob")).toEqual(["bob", "alice"]);
    expect(parseCandidates("bob,bob", false)).toEqual(["bob", "bob"]);
    expect(parseCandidates("3..1")).toEqual(["3", "2", "1"]);
  });
  it("calculates all attack counts", () => {
    expect(requestCount("sniper", positions)).toBe(5);
    expect(requestCount("battering_ram", positions)).toBe(2);
    expect(requestCount("pitchfork", positions)).toBe(2);
    expect(requestCount("cluster_bomb", positions)).toBe(6);
  });
  it("keeps pitchfork pairing and cluster order", () => {
    expect(previewCombinations("pitchfork", positions)).toEqual([
      { username: "alice", password: "one" },
      { username: "bob", password: "two" },
    ]);
    expect(previewCombinations("cluster_bomb", positions, 3)[2]).toEqual({
      username: "alice", password: "three",
    });
  });
  it("applies processing rules in order", () => {
    expect(processCandidate(" Ab ", [
      { type: "lower" },
      { type: "prefix", value: "x-" },
      { type: "suffix", value: "-z" },
    ])).toBe("x-ab-z");
  });
});
