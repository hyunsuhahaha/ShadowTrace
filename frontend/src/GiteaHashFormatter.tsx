import { useState } from "react";
import { giteaHashToHashcatLine } from "./giteaHash";

// A raw `sqlite3 gitea.db "select passwd,salt from user"` dump gives hex
// columns, not something hashcat -m 10900 accepts directly — this
// re-encodes them into that mode's native line so the result can be pasted
// straight into the Hash Cracking workspace (which auto-detects it).
export default function GiteaHashFormatter() {
  const [passwdHex, setPasswdHex] = useState("");
  const [saltHex, setSaltHex] = useState("");
  const [iterations, setIterations] = useState("50000");

  const line = giteaHashToHashcatLine(passwdHex, saltHex, iterations);

  return (
    <section className="netexecCredCheck" aria-labelledby="gitea-hash-heading">
      <header>
        <h2 id="gitea-hash-heading">Gitea 비밀번호 해시 변환 (hashcat -m 10900용)</h2>
        <small>gitea.db의 user 테이블에서 얻은 passwd·salt 16진수 컬럼을 hashcat -m 10900
          입력 형식으로 재인코딩합니다. 반복 횟수는 Gitea 기본값인 50000입니다.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={passwdHex} onChange={(e) => setPasswdHex(e.target.value)}
          placeholder="passwd (hex)" aria-label="passwd (hex)" />
        <input value={saltHex} onChange={(e) => setSaltHex(e.target.value)}
          placeholder="salt (hex)" aria-label="salt (hex)" />
        <input value={iterations} onChange={(e) => setIterations(e.target.value)}
          placeholder="반복 횟수" aria-label="반복 횟수" />
      </div>
      {(passwdHex.trim() || saltHex.trim()) && (
        line
          ? <p className="netexecEvidenceMsg">hashcat 입력: <code>{line}</code></p>
          : <p role="alert">변환 실패 — hex 값과 반복 횟수를 확인하세요.</p>
      )}
    </section>
  );
}
