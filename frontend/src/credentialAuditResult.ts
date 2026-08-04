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
