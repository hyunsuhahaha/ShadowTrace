import { useState } from "react";
import { lfiPayloadCategories } from "./lfiPayloads";

// Same shape as SqlPayloadReference: staging text into Intruder's candidate
// list, never auto-detecting or auto-sending. Traversal depth and target
// file are independent axes, so categories are meant to be combined by hand
// (find the depth first, then swap in a target file) rather than run as one
// giant combined wordlist.
export default function LfiPayloadReference({ onSendToIntruder }: {
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
    <div className="sqlPayloadReference" aria-labelledby="lfi-payload-heading">
      <div className="webSectionTitle">
        <span>LFI 페이로드 참고</span>
        <h2 id="lfi-payload-heading">페이로드 카탈로그</h2>
        <p>
          복사해서 위 Request 편집기에 붙여넣거나, Intruder로 보내 요청 위치
          <code>{"{{position_1}}"}</code>의 후보 값으로 채운 뒤 직접 검토하고 전송하세요.
          경로 깊이(traversal-depth)로 먼저 몇 단계 위가 웹 루트인지 찾고, 그 뒤 대상 OS의
          파일 카테고리로 교체하는 순서를 권장합니다.
        </p>
      </div>
      {lfiPayloadCategories.map((category) => (
        <details key={category.id} className="sqlPayloadCategory">
          <summary>
            <b>{category.title}</b>
            <small>{category.targets.join(" · ")}</small>
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
