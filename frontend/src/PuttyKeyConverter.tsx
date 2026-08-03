import { useEffect, useState } from "react";
import { api } from "./api";

type ConvertResult = { installed: boolean; private_key: string | null; stderr?: string };

// A saved PuTTY session or Pageant export leaves a .ppk private key, which
// ssh/impacket won't read directly — puttygen converts it to OpenSSH format
// in one step. The .ppk format has three incompatible versions, so this
// wraps puttygen rather than parsing it by hand.
export default function PuttyKeyConverter() {
  const [ppk, setPpk] = useState("");
  const [result, setResult] = useState<ConvertResult>();
  const [checked, setChecked] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const value = ppk.trim();
    if (!value) {
      setResult(undefined);
      setChecked(false);
      setError("");
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      void api<ConvertResult>("/decoders/putty-to-openssh", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ppk_content: value }),
      }).then((data) => {
        if (cancelled) return;
        setResult(data);
        setChecked(true);
        setError("");
      }).catch((reason) => {
        if (cancelled) return;
        setChecked(false);
        setError(String(reason).replace(/^Error:\s*/, ""));
      });
    }, 400);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [ppk]);

  return (
    <section className="netexecCredCheck" aria-labelledby="putty-key-heading">
      <header>
        <h2 id="putty-key-heading">PuTTY 개인 키 변환 (.ppk → OpenSSH)</h2>
        <small>대상에서 찾은 .ppk 파일 내용을 그대로 붙여넣으면 ssh/impacket에서 바로 쓸 수 있는
          OpenSSH 형식으로 변환합니다.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <textarea rows={6} value={ppk} onChange={(e) => setPpk(e.target.value)}
          placeholder="PuTTY-User-Key-File-3: ssh-rsa..." aria-label=".ppk 파일 내용" />
      </div>
      {checked && result && !result.installed &&
        <div className="empty">puttygen이 설치되어 있지 않습니다 (sudo apt install putty-tools).</div>}
      {checked && result?.installed && result.private_key &&
        <p className="netexecEvidenceMsg">변환됨:<br /><code>{result.private_key}</code></p>}
      {checked && result?.installed && !result.private_key &&
        <p role="alert">변환 실패 — 유효한 .ppk 내용인지 확인하세요.
          {result.stderr && <pre>{result.stderr}</pre>}</p>}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
