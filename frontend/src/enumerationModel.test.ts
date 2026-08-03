import {describe, expect, it} from "vitest";
import {impacketAuthArgs, isNtlmHash, shellQuote} from "./enumerationModel";

describe("shellQuote", () => {
  it("keeps quotes and shell operators inside one POSIX word", () => {
    expect(shellQuote("a'b; $(id)")).toBe("'a'\\''b; $(id)'");
  });
});

describe("isNtlmHash", () => {
  it("recognizes a bare 32-hex NT hash", () => {
    expect(isNtlmHash("32693b11e6aa90eb43d32c72a07ceea6")).toBe(true);
    expect(isNtlmHash("  32693B11E6AA90EB43D32C72A07CEEA6  ")).toBe(true);
  });

  it("rejects plain passwords, even hex-ish or wrong-length ones", () => {
    expect(isNtlmHash("s3rvice")).toBe(false);
    expect(isNtlmHash("deadbeef")).toBe(false);
    expect(isNtlmHash("")).toBe(false);
  });
});

describe("impacketAuthArgs", () => {
  it("builds a normal domain/user:password@host identity for a plain password", () => {
    expect(impacketAuthArgs("htb.local", "svc-alfresco", "s3rvice", "10.10.10.161"))
      .toBe(shellQuote("htb.local/svc-alfresco:s3rvice@10.10.10.161"));
  });

  it("omits the domain segment when none is set", () => {
    expect(impacketAuthArgs("", "administrator", "P@ss", "10.10.10.161"))
      .toBe(shellQuote("administrator:P@ss@10.10.10.161"));
  });

  it("switches to -hashes pass-the-hash when the secret looks like an NT hash", () => {
    expect(impacketAuthArgs(
      "htb.local", "Administrator", "32693b11e6aa90eb43d32c72a07ceea6", "10.10.10.161",
    )).toBe(
      `${shellQuote("htb.local/Administrator@10.10.10.161")} -hashes ${shellQuote(":32693b11e6aa90eb43d32c72a07ceea6")}`,
    );
  });
});
