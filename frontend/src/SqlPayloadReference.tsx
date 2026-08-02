import { useState } from "react";
import { sqlPayloadCategories } from "./sqlPayloads";

// Copy-only reference for manual SQL injection: SQLmap and other automated
// SQLi tools are explicitly banned on the OSCP exam, so this exists to
// speed up the manual workflow (paste into the request editor, then send)
// instead of automating any part of it.
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
        <span>수동 SQLi 참고 (SQLmap 미사용)</span>
        <h2 id="sql-payload-heading">페이로드 카탈로그</h2>
        <p>
          SQLmap을 비롯한 자동 SQLi 도구는 OSCP 시험에서 금지되어 있어, 여기 있는 값은
          복사해서 위 Request 편집기에 직접 붙여넣고 Send로 수동 확인하는 용도입니다.
          자동으로 요청을 보내지 않습니다.
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
