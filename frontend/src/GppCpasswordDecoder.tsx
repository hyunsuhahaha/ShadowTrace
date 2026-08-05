import { useEffect, useState } from "react";
import { decodeGppCpassword } from "./gppCpassword";

// Groups.xml (and ScheduledTasks.xml, etc.) under a domain's SYSVOL share
// still turns up "cpassword" attributes on older/misconfigured DCs — worth
// checking every time SMB is in play, since decoding it is instant.
export default function GppCpasswordDecoder() {
  const [input, setInput] = useState("");
  const [decoded, setDecoded] = useState<string>();
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    const value = input.trim();
    if (!value) {
      setDecoded(undefined);
      setChecked(false);
      return;
    }
    let cancelled = false;
    void decodeGppCpassword(value).then((result) => {
      if (cancelled) return;
      setDecoded(result);
      setChecked(true);
    });
    return () => { cancelled = true; };
  }, [input]);

  return (
    <section className="netexecCredCheck" aria-labelledby="gpp-heading">
      <header>
        <h2 id="gpp-heading">GPP cpassword 디코드</h2>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="예: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh..." aria-label="cpassword 값" />
      </div>
      {checked && (
        decoded != null
          ? <p className="netexecEvidenceMsg">평문: <code>{decoded}</code></p>
          : <p role="alert">복호화 실패 — 유효한 cpassword 값이 아닙니다.</p>
      )}
    </section>
  );
}
