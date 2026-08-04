import { useState } from "react";
import { sqlPayloadCategories } from "./sqlPayloads";

// Sending a payload to Intruder only stages text in the candidate list — the
// user still marks the injection point, reviews the request count, and
// confirms before anything is sent. See sqlPayloads.ts for why there is no
// automatic detection or exploitation here (SQLmap and similar tools are
// banned on the OSCP exam).
export default function SqlPayloadReference({ onSendToIntruder }: {
  onSendToIntruder?: (payloads: string[]) => void;
}) {
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
          복사해서 위 Request 편집기에 붙여넣거나, Intruder로 보내 요청 위치
          <code>{"{{position_1}}"}</code>의 후보 값으로 채운 뒤 직접 검토하고 전송하세요.
          SQLmap 등 자동 SQLi 도구는 시험 규정상 금지되어 있어 자동 탐지·전송 기능은 없습니다.
        </p>
      </div>
      {sqlPayloadCategories.map((category) => (
        <details key={category.id} className="sqlPayloadCategory">
          <summary>
            <b>{category.title}</b>
            <small>{category.engines.join(" · ")}</small>
          </summary>
          <p>{category.description}</p>
          {onSendToIntruder && <button type="button" className="sqlPayloadCategorySend"
            onClick={() => onSendToIntruder(category.payloads.map((item) => item.payload))}>
            카테고리 전체를 Intruder 후보로 보내기 →
          </button>}
          <div className="sqlPayloadList">
            {category.payloads.map((item) => (
              <div key={item.label} className="sqlPayloadRow">
                <div>
                  <b>{item.label}</b>
                  <code>{item.payload}</code>
                  {item.note && <small>{item.note}</small>}
                </div>
                <div className="sqlPayloadActions">
                  <button onClick={() => void copy(item.payload)}>
                    {copied === item.payload ? "복사됨" : "복사"}
                  </button>
                  {onSendToIntruder && <button onClick={() => onSendToIntruder([item.payload])}>
                    Intruder로
                  </button>}
                </div>
              </div>
            ))}
          </div>
        </details>
      ))}
    </div>
  );
}
