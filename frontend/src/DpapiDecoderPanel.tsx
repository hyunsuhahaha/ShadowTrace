import { useState } from "react";
import { api } from "./api";

type MasterkeyResult = {
  installed: boolean; decrypted_key: string | null; raw_output: string; exit_code?: number;
};
type CredentialResult = { installed: boolean; raw_output: string; exit_code?: number };

// DPAPI-protected credentials (Credential Manager blobs, saved browser/RDP
// secrets) are a very common find once you have a shell — but decrypting
// them is a two-step chain (masterkey -> key, then credential -> plaintext)
// and the crypto (MS-BKRP masterkey derivation) isn't something to
// reimplement by hand, so this wraps impacket-dpapi rather than the
// browser-side approach the other decoders use. Only the local
// user-password masterkey path is covered (-sid/-password), not the domain
// backup-key or SYSTEM/SECURITY-hive paths impacket-dpapi also supports.
export default function DpapiDecoderPanel() {
  const [masterkeyB64, setMasterkeyB64] = useState("");
  const [sid, setSid] = useState("");
  const [password, setPassword] = useState("");
  const [masterkeyBusy, setMasterkeyBusy] = useState(false);
  const [masterkeyResult, setMasterkeyResult] = useState<MasterkeyResult>();
  const [masterkeyError, setMasterkeyError] = useState("");

  const [credentialB64, setCredentialB64] = useState("");
  const [keyHex, setKeyHex] = useState("");
  const [credentialBusy, setCredentialBusy] = useState(false);
  const [credentialResult, setCredentialResult] = useState<CredentialResult>();
  const [credentialError, setCredentialError] = useState("");

  const decryptMasterkey = async () => {
    if (!masterkeyB64.trim() || !sid.trim() || !password.trim()) return;
    setMasterkeyBusy(true); setMasterkeyError("");
    try {
      setMasterkeyResult(await api<MasterkeyResult>("/decoders/dpapi-masterkey", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          masterkey_b64: masterkeyB64.trim(), sid: sid.trim(), password: password.trim(),
        }),
      }));
    } catch (reason) {
      setMasterkeyError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setMasterkeyBusy(false);
    }
  };

  const decryptCredential = async () => {
    if (!credentialB64.trim() || !keyHex.trim()) return;
    setCredentialBusy(true); setCredentialError("");
    try {
      setCredentialResult(await api<CredentialResult>("/decoders/dpapi-credential", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential_b64: credentialB64.trim(), key_hex: keyHex.trim() }),
      }));
    } catch (reason) {
      setCredentialError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setCredentialBusy(false);
    }
  };

  return (
    <section className="netexecCredCheck" aria-labelledby="dpapi-heading">
      <header>
        <h2 id="dpapi-heading">DPAPI 마스터키 · Credential 복호화</h2>
        <small>마스터키·credential 파일은 대상에서 base64로 인코딩해 붙여넣으세요 (예: PowerShell
          [Convert]::ToBase64String([IO.File]::ReadAllBytes("경로"))).</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <textarea rows={3} value={masterkeyB64} onChange={(e) => setMasterkeyB64(e.target.value)}
          placeholder="마스터키 파일 (base64)" aria-label="마스터키 파일 (base64)" />
        <input value={sid} onChange={(e) => setSid(e.target.value)}
          placeholder="사용자 SID" aria-label="사용자 SID" />
        <input value={password} onChange={(e) => setPassword(e.target.value)}
          placeholder="사용자 비밀번호" aria-label="마스터키용 비밀번호" />
        <button disabled={masterkeyBusy || !masterkeyB64.trim() || !sid.trim() || !password.trim()}
          onClick={() => void decryptMasterkey()}>
          {masterkeyBusy ? "복호화 중…" : "마스터키 복호화"}
        </button>
      </div>
      {masterkeyResult && !masterkeyResult.installed &&
        <div className="empty">impacket-dpapi가 설치되어 있지 않습니다.</div>}
      {masterkeyResult?.installed && masterkeyResult.decrypted_key && (
        <p className="netexecEvidenceMsg">
          복호화된 키: <code>{masterkeyResult.decrypted_key}</code>{" "}
          <button type="button" onClick={() => setKeyHex(masterkeyResult.decrypted_key!)}>
            아래 Credential 복호화에 사용
          </button>
        </p>
      )}
      {masterkeyResult?.installed && !masterkeyResult.decrypted_key &&
        <p role="alert">복호화 실패 — SID·비밀번호나 파일을 확인하세요.
          <pre>{masterkeyResult.raw_output}</pre></p>}
      {masterkeyError && <p role="alert">{masterkeyError}</p>}

      <div className="netexecCredForm netexecCredForm--save">
        <textarea rows={3} value={credentialB64} onChange={(e) => setCredentialB64(e.target.value)}
          placeholder="Credential 파일 (base64)" aria-label="Credential 파일 (base64)" />
        <input value={keyHex} onChange={(e) => setKeyHex(e.target.value)}
          placeholder="복호화된 마스터키 (hex)" aria-label="복호화된 마스터키 (hex)" />
        <button disabled={credentialBusy || !credentialB64.trim() || !keyHex.trim()}
          onClick={() => void decryptCredential()}>
          {credentialBusy ? "복호화 중…" : "Credential 복호화"}
        </button>
      </div>
      {credentialResult && !credentialResult.installed &&
        <div className="empty">impacket-dpapi가 설치되어 있지 않습니다.</div>}
      {credentialResult?.installed && <pre>{credentialResult.raw_output}</pre>}
      {credentialError && <p role="alert">{credentialError}</p>}
    </section>
  );
}
