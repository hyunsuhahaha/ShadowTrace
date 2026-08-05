import { useState } from "react";
import { decodeCiscoType7 } from "./ciscoType7";

// A leaked router/switch config (common file-share or web loot) often carries
// "password 7 <hex>" lines. This decodes instantly client-side — it's a
// reversible XOR, not a hash, so there's nothing to crack or send anywhere.
export default function CiscoType7Decoder() {
  const [input, setInput] = useState("");
  const decoded = input.trim() ? decodeCiscoType7(input) : undefined;

  return (
    <section className="netexecCredCheck" aria-labelledby="cisco-type7-heading">
      <header>
        <h2 id="cisco-type7-heading">Cisco Type 7 비밀번호 디코드</h2>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="예: 0242114B0E143F015F5D1E161713" aria-label="Cisco type 7 값" />
      </div>
      {input.trim() && (
        decoded != null
          ? <p className="netexecEvidenceMsg">평문: <code>{decoded}</code></p>
          : <p role="alert">복호화 실패 — seed(앞 2자리)+hex 형식이 아닙니다.</p>
      )}
    </section>
  );
}
