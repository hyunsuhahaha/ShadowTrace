import { useEffect, useState } from "react";
import { api } from "./api";

// Pre-AES Roundcube builds store the IMAP password in the session table's
// "vars" column, DES-EDE3-CBC encrypted with config.inc.php's raw des_key —
// no KDF, so once that key is read out of a foothold shell, every session
// blob dumped from the DB decodes instantly. The cipher (3DES) isn't
// available through the browser's Web Crypto API, so unlike the GPP/Cisco
// decoders next to this one, this round-trips through a backend endpoint.
export default function RoundcubeDesDecoder() {
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [decoded, setDecoded] = useState<string>();
  const [checked, setChecked] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const keyValue = key.trim();
    const blob = value.trim();
    if (!keyValue || !blob) {
      setDecoded(undefined);
      setChecked(false);
      setError("");
      return;
    }
    let cancelled = false;
    void api<{ plaintext: string | null }>("/decoders/roundcube-des", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: keyValue, value: blob }),
    }).then((result) => {
      if (cancelled) return;
      setDecoded(result.plaintext ?? undefined);
      setChecked(true);
      setError("");
    }).catch((reason) => {
      if (cancelled) return;
      setChecked(false);
      setError(String(reason).replace(/^Error:\s*/, ""));
    });
    return () => { cancelled = true; };
  }, [key, value]);

  return (
    <section className="netexecCredCheck" aria-labelledby="roundcube-des-heading">
      <header>
        <h2 id="roundcube-des-heading">Roundcube 세션 비밀번호 복호화 (3DES)</h2>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={key} onChange={(e) => setKey(e.target.value)}
          placeholder="des_key (24바이트 문자열)" aria-label="des_key" />
        <input value={value} onChange={(e) => setValue(e.target.value)}
          placeholder="암호화된 값 (base64)" aria-label="암호화된 값" />
      </div>
      {checked && (
        decoded != null
          ? <p className="netexecEvidenceMsg">평문: <code>{decoded}</code></p>
          : <p role="alert">복호화 실패 — 키 길이(24바이트)나 값을 확인하세요.</p>
      )}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
