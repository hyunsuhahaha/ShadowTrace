import { useState } from "react";
import { api } from "./api";

type LsassResult = { installed: boolean; raw_output: string; stderr?: string };

// A dumped lsass.exe process (procdump, comsvcs.dll MiniDump, Task Manager)
// is one of the highest-value credential finds on a Windows box — pypykatz
// re-implements Mimikatz's MSV/wdigest/Kerberos/DPAPI secret extraction in
// pure Python, so this wraps it rather than parsing minidumps by hand.
// Unlike the paste-based decoders next to this one, the dump is uploaded as
// a file since it's binary and can run to hundreds of MB.
export default function PypykatzLsassPanel() {
  const [file, setFile] = useState<File>();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LsassResult>();
  const [error, setError] = useState("");

  const upload = async () => {
    if (!file) return;
    setBusy(true); setError("");
    try {
      const body = new FormData();
      body.append("file", file);
      setResult(await api<LsassResult>("/decoders/pypykatz-lsass", { method: "POST", body }));
    } catch (reason) {
      setError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="netexecCredCheck" aria-labelledby="pypykatz-heading">
      <header>
        <h2 id="pypykatz-heading">LSASS 덤프 분석 (pypykatz)</h2>
        <small>procdump·comsvcs.dll MiniDump 등으로 얻은 lsass.exe 덤프 파일을 업로드하면
          NTLM 해시·Kerberos 티켓 등 저장된 자격증명을 추출합니다.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input type="file" aria-label="LSASS 덤프 파일"
          onChange={(e) => setFile(e.target.files?.[0])} />
        <button disabled={busy || !file} onClick={() => void upload()}>
          {busy ? "분석 중…" : "업로드 및 분석"}
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
      {result && !result.installed &&
        <div className="empty">pypykatz가 설치되어 있지 않습니다 (sudo apt install python3-pypykatz).</div>}
      {result?.installed && <pre>{result.raw_output}</pre>}
    </section>
  );
}
