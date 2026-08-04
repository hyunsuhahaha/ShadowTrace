import {describe, expect, it} from "vitest";
import {summarizeCredentialAudit} from "./credentialAuditResult";

describe("credential audit result summary", () => {
  it("reports when FTP anonymous login is allowed", () => {
    expect(summarizeCredentialAudit(
      "ftp-anon",
      "| ftp-anon: Anonymous FTP login allowed (FTP code 230)\n",
      "",
    )).toEqual({
      status: "exposed",
      label: "로그인 성공 · anonymous / IEUser@",
      credential: {username: "anonymous", password: "IEUser@"},
    });
  });

  it("reports a completed FTP check without an allowed marker as denied", () => {
    expect(summarizeCredentialAudit(
      "ftp-anon",
      "21/tcp open ftp\n",
      "",
    )).toEqual({
      status: "clear",
      label: "익명 로그인 허용되지 않음",
    });
  });

  it("summarizes discovered credentials from brute audit output", () => {
    expect(summarizeCredentialAudit(
      "ftp-default-audit",
      "| ftp-brute:\n|   Accounts:\n|     admin:password - Valid credentials\n",
      "",
    )).toEqual({
      status: "exposed",
      label: "로그인 성공 · admin / password",
      credential: {username: "admin", password: "password"},
    });
  });

  it("does not report success from nmap's own 'No valid accounts found' failure message", () => {
    expect(summarizeCredentialAudit(
      "mysql-default-audit",
      "| mysql-brute: \n|   Accounts: No valid accounts found \n" +
        "|   Statistics: Performed 0 guesses in 5 seconds, average tps: 0.0\n" +
        "|_  ERROR: The service seems to have failed or is heavily firewalled...\n",
      "",
    )).toEqual({
      status: "clear",
      label: "유효한 인증 정보 발견되지 않음",
    });
  });
});
