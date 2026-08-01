import {describe, expect, it} from "vitest";
import {getCredentialAuditProfile} from "./credentialAudit";

describe("protocol credential audit copy", () => {
  it("uses anonymous as the complete FTP protocol dataset", () => {
    const ftp = getCredentialAuditProfile("ftp");
    const telnet = getCredentialAuditProfile("telnet");
    expect(ftp.identities).toBe("anonymous");
    expect(ftp.identities).not.toContain("root");
    expect(ftp.secrets).toContain("anonymous@");
    expect(telnet.identities).toBe("admin · root · cisco · support");
  });

  it("does not invent usernames for password-only protocols", () => {
    expect(getCredentialAuditProfile("redis").identities).toContain("사용자명 없음");
    expect(getCredentialAuditProfile("vnc").identities).toBe("사용자명 없음");
    expect(getCredentialAuditProfile("snmp").secretLabel).toContain("Community 후보");
  });

  it("shows protocol-specific SNMP and RDP candidates", () => {
    expect(getCredentialAuditProfile("snmp").secrets).toContain("public · private · snmpd");
    expect(getCredentialAuditProfile("ms-wbt-server").identities).toContain("administrator");
    expect(getCredentialAuditProfile("https").title).toContain("HTTP");
  });

  it("does not reuse one generic dataset across protocols", () => {
    expect(getCredentialAuditProfile("ssh").identities)
      .not.toBe(getCredentialAuditProfile("mysql").identities);
    expect(getCredentialAuditProfile("mysql").identities)
      .not.toBe(getCredentialAuditProfile("postgresql").identities);
  });
});
