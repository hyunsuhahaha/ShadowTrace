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

  it("reports MySQL accounts with an empty password", () => {
    expect(summarizeCredentialAudit(
      "mysql-empty-password",
      "3306/tcp open  mysql\n| mysql-empty-password:\n" +
        "|   anonymous account has empty password\n|_  root account has empty password\n",
      "",
    )).toEqual({
      status: "exposed",
      label: "빈 비밀번호 허용됨 · anonymous, root",
      credential: {username: "anonymous", password: ""},
    });
  });

  it("reports MySQL as clear when the empty-password script finds nothing", () => {
    expect(summarizeCredentialAudit(
      "mysql-empty-password",
      "3306/tcp open  mysql\n",
      "",
    )).toEqual({status: "clear", label: "빈 비밀번호 허용되지 않음"});
  });

  it("reports the MSSQL sa account when its password is empty", () => {
    expect(summarizeCredentialAudit(
      "mssql-empty-password",
      "| ms-sql-empty-password:\n|   [10.0.0.1\\SQLEXPRESS]\n|_    sa:<empty> => Login Success\n",
      "",
    )).toEqual({
      status: "exposed",
      label: "빈 비밀번호 허용됨 · sa",
      credential: {username: "sa", password: ""},
    });
  });

  it("reports MSSQL as clear when sa's password isn't blank", () => {
    expect(summarizeCredentialAudit(
      "mssql-empty-password",
      "1433/tcp open  ms-sql-s\n",
      "",
    )).toEqual({status: "clear", label: "빈 비밀번호 허용되지 않음"});
  });

  it("reports the winning candidate from a direct mysql credential probe", () => {
    expect(summarizeCredentialAudit(
      "mysql-credential-probe",
      "[+] SUCCESS root:<empty>\nCURRENT_USER()\tVERSION()\nroot@%\t10.3.27-MariaDB\n",
      "",
    )).toEqual({
      status: "exposed",
      label: "로그인 성공 · root / (빈 비밀번호)",
      credential: {username: "root", password: ""},
    });
  });

  it("reports a non-blank winning password from the credential probe", () => {
    expect(summarizeCredentialAudit(
      "mysql-credential-probe",
      "[-] FAILED root:<empty>\n[+] SUCCESS mysql:mysql\nCURRENT_USER()\nmysql@%\n",
      "",
    )).toEqual({
      status: "exposed",
      label: "로그인 성공 · mysql / mysql",
      credential: {username: "mysql", password: "mysql"},
    });
  });

  it("reports the credential probe as clear when every candidate fails", () => {
    expect(summarizeCredentialAudit(
      "mysql-credential-probe",
      "[-] FAILED root:<empty>\n[-] FAILED root:root\n" +
        "[-] No valid MySQL credentials found among 12 candidates.\n",
      "",
    )).toEqual({status: "clear", label: "유효한 인증 정보 발견되지 않음"});
  });

  it("does not report success from nmap's own 'No valid accounts found' failure message", () => {
    expect(summarizeCredentialAudit(
      "ftp-default-audit",
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
