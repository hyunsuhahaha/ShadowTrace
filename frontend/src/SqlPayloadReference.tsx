import { useState } from "react";
import { sqlPayloadCategories } from "./sqlPayloads";

// See sqlPayloads.ts for why this is copy-only.
export default function SqlPayloadReference() {
  const [copied, setCopied] = useState<string>();
  const copy = async (payload: string) => {
    await navigator.clipboard.writeText(payload);
    setCopied(payload);
    window.setTimeout(() => setCopied((current) =>
      current === payload ? undefined : current), 1500);
  };
  return (
    <div className="sqlPayloadReference" aria-labelledby="sql-payload-heading">
      <div className="webSectionTitle">
        <span>SQLi 페이로드 참고</span>
        <h2 id="sql-payload-heading">페이로드 카탈로그</h2>
        <p>
          복사해서 위 Request 편집기에 붙여넣고 직접 Send로 확인하세요.
          SQLmap 등 자동 SQLi 도구는 시험 규정상 금지되어 있어 자동 전송 기능은 없습니다.
        </p>
      </div>
      {sqlPayloadCategories.map((category) => (
        <details key={category.id} className="sqlPayloadCategory">
          <summary>
            <b>{category.title}</b>
            <small>{category.engines.join(" · ")}</small>
          </summary>
          <p>{category.description}</p>
          <div className="sqlPayloadList">
            {category.payloads.map((item) => (
              <div key={item.label} className="sqlPayloadRow">
                <div>
                  <b>{item.label}</b>
                  <code>{item.payload}</code>
                  {item.note && <small>{item.note}</small>}
                </div>
                <button onClick={() => void copy(item.payload)}>
                  {copied === item.payload ? "복사됨" : "복사"}
                </button>
              </div>
            ))}
          </div>
        </details>
      ))}
    </div>
  );
}
