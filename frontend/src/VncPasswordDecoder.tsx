import { useEffect, useState } from "react";
import { api } from "./api";

// VNC (RealVNC/TightVNC/UltraVNC) obfuscates its stored password with
// DES-ECB under a single fixed, publicly-documented key — same "static
// key, instant decrypt" shape as the GPP cpassword and Cisco Type 7
// decoders. DES-ECB isn't in the Web Crypto API's algorithm set though, so
// like the Roundcube decoder this needs a small backend endpoint.
export default function VncPasswordDecoder() {
  const [input, setInput] = useState("");
  const [decoded, setDecoded] = useState<string>();
  const [checked, setChecked] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const value = input.trim();
    if (!value) {
      setDecoded(undefined);
      setChecked(false);
      setError("");
      return;
    }
    let cancelled = false;
    void api<{ plaintext: string | null }>("/decoders/vnc-password", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext_hex: value }),
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
  }, [input]);

  return (
    <section className="netexecCredCheck" aria-labelledby="vnc-password-heading">
      <header>
        <h2 id="vnc-password-heading">VNC 비밀번호 디코드</h2>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="예: 6bcf2a4b6e5aca7f" aria-label="VNC 비밀번호 값 (hex)" />
      </div>
      {checked && (
        decoded != null
          ? <p className="netexecEvidenceMsg">평문: <code>{decoded}</code></p>
          : <p role="alert">복호화 실패 — 8바이트 단위의 유효한 16진수 값인지 확인하세요.</p>
      )}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
