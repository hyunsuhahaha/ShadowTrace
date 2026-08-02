import {describe, expect, it} from "vitest";
import {shellQuote} from "./enumerationModel";

describe("shellQuote", () => {
  it("keeps quotes and shell operators inside one POSIX word", () => {
    expect(shellQuote("a'b; $(id)")).toBe("'a'\\''b; $(id)'");
  });
});
