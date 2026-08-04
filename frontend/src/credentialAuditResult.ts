export type CredentialAuditSummary = {
  status: "exposed" | "clear";
  label: string;
  credential?: { username: string; password: string };
};

export function summarizeCredentialAudit(
  templateId: string,
  stdout: string,
  stderr: string,
): CredentialAuditSummary {
  const output = `${stdout}\n${stderr}`;
  if (templateId === "ftp-anon") {
    return /Anonymous FTP login allowed/i.test(output)
      ? {
          status: "exposed",
          label: "로그인 성공 · anonymous / IEUser@",
          credential: {username: "anonymous", password: "IEUser@"},
        }
      : {status: "clear", label: "익명 로그인 허용되지 않음"};
  }
  if (templateId === "mysql-empty-password") {
    // mysql-empty-password.nse prints one line per vulnerable account and
    // nothing at all when neither account is vulnerable — there's no
    // separate "not vulnerable" marker to look for.
    const accounts = [...output.matchAll(/(anonymous|root) account has empty password/gi)]
      .map((match) => match[1]);
    return accounts.length
      ? {
          status: "exposed",
          label: `빈 비밀번호 허용됨 · ${accounts.join(", ")}`,
          credential: {username: accounts[0], password: ""},
        }
      : {status: "clear", label: "빈 비밀번호 허용되지 않음"};
  }
  if (templateId === "mssql-empty-password") {
    // ms-sql-empty-password.nse reports a hit as "sa:<empty> => Login
    // Success"; like mysql-empty-password it prints nothing when sa's
    // password isn't blank (at default verbosity).
    return /sa:<empty>\s*=>\s*Login Success/i.test(output)
      ? {
          status: "exposed",
          label: "빈 비밀번호 허용됨 · sa",
          credential: {username: "sa", password: ""},
        }
      : {status: "clear", label: "빈 비밀번호 허용되지 않음"};
  }
  if (templateId === "mysql-root-connect") {
    // The mysql client refuses to connect with a plain error (e.g. "ERROR
    // 1045 (28000): Access denied...") when the login fails; anything else
    // means the SELECT actually ran, i.e. root has no password.
    return /error \d+/i.test(output)
      ? {status: "clear", label: "root 계정 빈 비밀번호로 접속 실패"}
      : {
          status: "exposed",
          label: "root 계정 빈 비밀번호로 접속 성공",
          credential: {username: "root", password: ""},
        };
  }
  if (!/(?:default-audit|community-audit)/i.test(templateId)) {
    return {status: "clear", label: "검사 완료 · 원문 확인"};
  }
  // nmap's brute library always reports a real find as "user:pass - Valid
  // credentials" on one line, so this pattern alone is sufficient — a looser
  // fallback that just searched for "Valid account" anywhere in the output
  // used to fire on nmap's own failure message "No valid accounts found",
  // since that phrase contains "valid account" as a substring.
  const credential = output.match(
    /([^\s:|]+):(.*?)\s+-\s+(?:Valid credentials|Valid account|Authentication succeeded)/i,
  );
  if (credential) {
    return {
      status: "exposed",
      label: `로그인 성공 · ${credential[1]} / ${credential[2] || "(빈 비밀번호)"}`,
      credential: {username: credential[1], password: credential[2]},
    };
  }
  return {status: "clear", label: "유효한 인증 정보 발견되지 않음"};
}
