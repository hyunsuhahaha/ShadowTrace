import { describe, expect, it } from "vitest";
import { getServiceGuidance } from "./serviceGuidance";

describe("service guidance", () => {
  it("provides manual Telnet steps without passwords or automatic input", () => {
    const guidance = getServiceGuidance("telnet", "10.10.10.23", 23);

    expect(guidance?.command).toBe("telnet 10.10.10.23 23");
    expect(guidance?.accountCandidates).toContain("root");
    expect(guidance?.steps.join(" ")).toContain("login:");
    expect(JSON.stringify(guidance)).not.toMatch(/password|비밀번호|auto.?type/i);
  });

  it("does not invent guidance for an unsupported service", () => {
    expect(getServiceGuidance("unknown", "10.10.10.10", 31337)).toBeNull();
  });

  it("does not present SMB connection guidance for MSRPC", () => {
    expect(getServiceGuidance("msrpc", "10.10.10.10", 135)).toBeNull();
    expect(getServiceGuidance("microsoft-ds", "10.10.10.10", 445)?.title)
      .toBe("SMB 수동 접속");
  });
});
